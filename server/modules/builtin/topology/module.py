"""
Built-in Topology (Network Plan) module.

Builds and maintains the network graph used by the frontend (Cytoscape.js)
and the auto-generated network plan documents.

Graph format:
  nodes — hosts, network devices, network segments (subnets)
  edges — ARP, CDP/LLDP, routing, L2 adjacency

The module also generates a Markdown network plan on demand via export().
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, NetworkDevice, Network, ScanResult


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-topology",
        version="1.0.0",
        description="Network topology builder and network plan generator.",
        author="Discoverykastle",
        capabilities=[ModuleCapability.TOPOLOGY, ModuleCapability.EXPORT],
        builtin=True,
    )

    # ------------------------------------------------------------------
    # Event hooks — auto-link devices and subnets into the graph
    # ------------------------------------------------------------------

    async def on_device_found(
        self, device: "NetworkDevice", db: "AsyncSession"
    ) -> None:
        """
        When a network device is discovered, try to infer topology edges
        from its structured_data (interfaces, neighbors, ARP table).
        """
        if not device.structured_data:
            return

        data = json.loads(device.structured_data)
        neighbors = data.get("neighbors", [])

        for neighbor in neighbors:
            neighbor_ip = neighbor.get("ip")
            if not neighbor_ip:
                continue
            await self._ensure_topology_edge(
                db,
                source_ip=device.ip_address,
                target_ip=neighbor_ip,
                edge_type=neighbor.get("protocol", "lldp"),
            )

    async def on_scan_complete(
        self, result: "ScanResult", db: "AsyncSession"
    ) -> None:
        """Rebuild topology edges from ARP data when a scan finishes."""
        pass  # Implemented via the topology API endpoint rebuild trigger

    # ------------------------------------------------------------------
    # Graph builder — called by the topology API
    # ------------------------------------------------------------------

    async def build_graph(self, db: "AsyncSession") -> dict[str, Any]:
        """
        Return a graph dict consumable by Cytoscape.js:
          { "nodes": [...], "edges": [...] }
        """
        from server.models.host import Host
        from server.models.device import NetworkDevice
        from server.models.network import Network, TopologyEdge

        nodes: list[dict] = []
        edges: list[dict] = []

        # --- Hosts ---
        host_rows = await db.execute(select(Host))
        for host in host_rows.scalars():
            label = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else str(host.id))
            nodes.append({
                "data": {
                    "id": f"host-{host.id}",
                    "label": label,
                    "type": "host",
                    "os": host.os,
                    "ip_addresses": host.ip_addresses,
                    "last_seen": host.last_seen.isoformat() if host.last_seen else None,
                }
            })

        # --- Network devices ---
        device_rows = await db.execute(select(NetworkDevice))
        for device in device_rows.scalars():
            label = device.hostname or device.ip_address
            nodes.append({
                "data": {
                    "id": f"device-{device.id}",
                    "label": label,
                    "type": "device",
                    "device_type": device.device_type,
                    "vendor": device.vendor,
                    "model": device.model,
                    "ip_address": device.ip_address,
                }
            })

        # --- Networks (subnets) ---
        network_rows = await db.execute(select(Network))
        for network in network_rows.scalars():
            nodes.append({
                "data": {
                    "id": f"network-{network.id}",
                    "label": network.description or network.cidr,
                    "type": "network",
                    "cidr": network.cidr,
                    "scan_authorized": network.scan_authorized,
                }
            })

        # --- Topology edges ---
        edge_rows = await db.execute(select(TopologyEdge))
        for edge in edge_rows.scalars():
            edges.append({
                "data": {
                    "id": f"edge-{edge.id}",
                    "source": f"host-{edge.source_host_id}",
                    "target": f"host-{edge.target_host_id}",
                    "type": edge.edge_type,
                }
            })

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Export — Markdown network plan
    # ------------------------------------------------------------------

    async def export(self, format: str, db: "AsyncSession") -> str | None:
        if format not in ("markdown", "md"):
            return None
        return await self._build_markdown_plan(db)

    async def _build_markdown_plan(self, db: "AsyncSession") -> str:
        from server.models.host import Host, Service
        from server.models.device import NetworkDevice
        from server.models.network import Network
        from server.models.vulnerability import Vulnerability
        from sqlalchemy import func
        from datetime import datetime

        lines: list[str] = [
            "# Network Plan",
            f"\n_Generated by Discoverykastle on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_\n",
        ]

        # --- Summary ---
        host_count = await db.scalar(select(func.count()).select_from(Host)) or 0
        device_count = await db.scalar(select(func.count()).select_from(NetworkDevice)) or 0
        network_count = await db.scalar(select(func.count()).select_from(Network)) or 0
        vuln_count = await db.scalar(select(func.count()).select_from(Vulnerability)) or 0

        lines += [
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Hosts | {host_count} |",
            f"| Network Devices | {device_count} |",
            f"| Networks | {network_count} |",
            f"| Vulnerabilities | {vuln_count} |",
            "",
        ]

        # --- Networks ---
        lines.append("## Network Segments\n")
        net_rows = await db.execute(select(Network).order_by(Network.cidr))
        for net in net_rows.scalars():
            auth = "✓ authorized" if net.scan_authorized else "⚠ not authorized"
            desc = f" — {net.description}" if net.description else ""
            lines.append(f"- **{net.cidr}**{desc} ({auth})")
        lines.append("")

        # --- Network Devices ---
        lines.append("## Network Devices\n")
        lines += [
            "| Hostname | IP | Vendor | Model | Firmware | Type |",
            "|----------|----|--------|-------|----------|------|",
        ]
        dev_rows = await db.execute(select(NetworkDevice).order_by(NetworkDevice.ip_address))
        for dev in dev_rows.scalars():
            lines.append(
                f"| {dev.hostname or '—'} | {dev.ip_address} | {dev.vendor or '—'} "
                f"| {dev.model or '—'} | {dev.firmware_version or '—'} | {dev.device_type or '—'} |"
            )
        lines.append("")

        # --- Hosts ---
        lines.append("## Hosts\n")
        lines += [
            "| FQDN / IP | OS | Services | Critical Vulns | Last Seen |",
            "|-----------|----|----------|----------------|-----------|",
        ]
        host_rows = await db.execute(select(Host).order_by(Host.last_seen.desc()))
        for host in host_rows.scalars():
            label = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else str(host.id))
            svc_count = await db.scalar(
                select(func.count()).where(Service.host_id == host.id)
            ) or 0
            crit_count = await db.scalar(
                select(func.count()).where(
                    Vulnerability.host_id == host.id,
                    Vulnerability.severity == "critical"
                )
            ) or 0
            last_seen = host.last_seen.strftime("%Y-%m-%d") if host.last_seen else "—"
            lines.append(
                f"| {label} | {host.os or '—'} | {svc_count} | {crit_count} | {last_seen} |"
            )
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    async def _ensure_topology_edge(
        self, db: "AsyncSession", source_ip: str, target_ip: str, edge_type: str
    ) -> None:
        from server.models.host import Host
        from server.models.network import TopologyEdge
        from sqlalchemy import and_

        src = await db.scalar(
            select(Host).where(Host.ip_addresses.contains([source_ip]))
        )
        tgt = await db.scalar(
            select(Host).where(Host.ip_addresses.contains([target_ip]))
        )
        if not src or not tgt:
            return

        existing = await db.scalar(
            select(TopologyEdge).where(
                and_(
                    TopologyEdge.source_host_id == src.id,
                    TopologyEdge.target_host_id == tgt.id,
                )
            )
        )
        if existing:
            return

        db.add(TopologyEdge(
            source_host_id=src.id,
            target_host_id=tgt.id,
            edge_type=edge_type,
        ))
        await db.flush()
