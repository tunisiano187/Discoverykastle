# Module System

Discoverykastle is extensible via a **module system** that lets you add custom alert rules, inventory enrichment, integrations (NetBox, ServiceNow, Splunk…), export formats, and data collectors — without modifying the core codebase.

---

## Architecture

```
server/modules/
├── base.py          # BaseModule — abstract class, event hooks
├── registry.py      # ModuleRegistry — singleton, event dispatcher
├── loader.py        # Discovers and loads modules at startup
└── builtin/         # Modules shipped with Discoverykastle
    ├── alerts/      # CVE alerts, agent offline, new host/network
    ├── inventory/   # Inventory enrichment (service counts, vuln summary)
    ├── topology/    # Network graph builder + Markdown network plan
    └── netbox/      # NetBox IPAM/DCIM sync
```

External modules are loaded from two additional sources:

1. **Python entry points** — pip-installable packages that declare `discoverykastle.modules` in their `pyproject.toml`
2. **Local directory** — subdirectories placed in `./modules/` at the project root (useful for quick custom scripts)

---

## Module Capabilities

| Capability | Purpose |
|---|---|
| `alert` | Generates alerts (persisted in DB + forwarded to notification channels) |
| `inventory` | Enriches inventory API responses via `get_inventory_extra()` |
| `topology` | Contributes to network graph and network plan |
| `integration` | Syncs with external tools (NetBox, CMDB, SIEM…) |
| `export` | Provides additional export formats via `export(format, db)` |
| `enrichment` | Enriches discovered data (GeoIP, WHOIS, threat intel feeds) |
| `collector` | Custom data collection tasks dispatched to agents |

---

## Built-in Modules

### `builtin-alerts`
Generates alerts for:
- Critical CVEs (CVSS ≥ 9.0) and High CVEs (CVSS ≥ 7.0)
- Agent going offline
- New host discovery
- New network segment discovery
- Scan failures

Forwards to Slack webhook and/or generic HTTP webhook when configured.

### `builtin-inventory`
Enriches host detail responses with:
- Service count
- Package count
- Vulnerability counts by severity

### `builtin-topology`
- Builds the Cytoscape.js-compatible network graph (`GET /api/v1/topology/graph`)
- Infers topology edges from device neighbor data (CDP/LLDP)
- Generates a Markdown **network plan** on demand (`GET /api/v1/topology/export/markdown`)

### `builtin-netbox`
Syncs discovered assets to NetBox:
- IP addresses → `ipam/ip-addresses/`
- Prefixes/subnets → `ipam/prefixes/`
- Network devices → `dcim/devices/`

Configure via environment variables:
```
DKASTLE_NETBOX_URL=https://netbox.example.com
DKASTLE_NETBOX_TOKEN=your-api-token
DKASTLE_NETBOX_SYNC_ENABLED=true
```

Trigger a full sync: `POST /api/v1/netbox/sync`

---

## Writing a Custom Module

### Option A — pip package (recommended for reuse/distribution)

```
my-dkastle-module/
├── pyproject.toml
└── my_module/
    └── module.py
```

`module.py`:
```python
from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

class Module(BaseModule):
    manifest = ModuleManifest(
        name="my-module",
        version="1.0.0",
        description="Enriches hosts with asset tags from our CMDB",
        author="your-team",
        capabilities=[ModuleCapability.INVENTORY],
    )

    async def get_inventory_extra(self, host_id, db):
        # Query your CMDB and return extra fields
        return {"asset_tag": "AST-1234", "owner": "IT Ops"}
```

`pyproject.toml`:
```toml
[project.entry-points."discoverykastle.modules"]
my-module = "my_module.module:Module"
```

Install with `pip install -e .` alongside Discoverykastle, then restart the server.

### Option B — Local directory (quick scripts)

Create `modules/my-module/module.py` with the same `Module` class.
Optionally add `modules/my-module/config.yaml` for configuration.

The loader picks it up automatically at startup.

---

## Event Hooks Reference

| Hook | Triggered when |
|---|---|
| `on_host_discovered(host, db)` | A new host is added or re-reported |
| `on_vulnerability_found(vuln, host, db)` | A CVE is linked to a host |
| `on_device_found(device, db)` | A network device is discovered |
| `on_network_discovered(network, db)` | A new subnet is found |
| `on_scan_complete(result, db)` | A scan task finishes |
| `on_agent_offline(agent_id, db)` | An agent misses heartbeats |

---

## Module Management API

| Endpoint | Description |
|---|---|
| `GET /api/v1/modules` | List all loaded modules |
| `GET /api/v1/modules/{name}` | Module detail |
| `GET /api/v1/netbox/status` | NetBox integration status |
| `POST /api/v1/netbox/sync` | Trigger full NetBox sync |
