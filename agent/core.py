"""
DK Agent — core runtime.

Handles:
  1. First-time enrollment  (POST /api/v1/agents/register)
  2. Heartbeat loop         (POST /api/v1/agents/{id}/heartbeat)
  3. Collector scheduler    (runs each enabled collector on its interval)

All HTTP calls use mTLS after enrollment.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
import ssl
import sys
import time
from pathlib import Path

import httpx

from agent.config import AgentConfig

logger = logging.getLogger(__name__)


class DKAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # HTTP client (plain before enrollment, mTLS after)
    # ------------------------------------------------------------------

    def _build_client(self, *, mtls: bool = True) -> httpx.AsyncClient:
        cfg = self.config
        if mtls and cfg.is_registered:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_cert_chain(cfg.agent_cert, cfg.agent_key)
            if cfg.agent_ca:
                ssl_ctx.load_verify_locations(cfg.agent_ca)
            else:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            return httpx.AsyncClient(
                base_url=cfg.server_url,
                verify=ssl_ctx,
                timeout=30,
            )
        return httpx.AsyncClient(
            base_url=cfg.server_url,
            verify=bool(self.config.agent_ca) or False,
            timeout=30,
        )

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------

    async def enroll(self) -> None:
        """
        Register with the DK server using the enrollment token.
        On success, writes agent_id + cert paths to the config file.
        """
        cfg = self.config
        if not cfg.server_url:
            raise RuntimeError("DKASTLE_SERVER_URL is not configured")
        if not cfg.enroll_token:
            raise RuntimeError(
                "DKASTLE_ENROLL_TOKEN is not set. "
                "Generate one in the DK dashboard (Agents → New enrollment token)."
            )

        logger.info("Enrolling with DK server at %s …", cfg.server_url)
        payload = {
            "hostname": socket.getfqdn(),
            "ip_address": _local_ip(),
            "os_platform": sys.platform,
            "os_version": platform.version(),
            "agent_version": _agent_version(),
        }

        async with self._build_client(mtls=False) as client:
            resp = await client.post(
                "/api/v1/agents/register",
                json=payload,
                headers={"Authorization": f"Bearer {cfg.enroll_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        # Save certificate files
        data_dir = cfg.data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        cert_path = data_dir / "agent.crt"
        key_path = data_dir / "agent.key"
        ca_path = data_dir / "ca.crt"

        cert_path.write_text(data["certificate"], encoding="utf-8")
        key_path.write_text(data["private_key"], encoding="utf-8")
        if data.get("ca_certificate"):
            ca_path.write_text(data["ca_certificate"], encoding="utf-8")

        # Restrict key file permissions on POSIX
        if sys.platform != "win32":
            key_path.chmod(0o600)

        updates = {
            "DKASTLE_AGENT_ID": data["agent_id"],
            "DKASTLE_AGENT_CERT": str(cert_path),
            "DKASTLE_AGENT_KEY": str(key_path),
        }
        if data.get("ca_certificate"):
            updates["DKASTLE_AGENT_CA"] = str(ca_path)

        cfg.save(updates)
        logger.info("Enrollment successful — agent ID: %s", data["agent_id"])

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        cfg = self.config

        if not cfg.is_registered:
            await self.enroll()

        logger.info(
            "DK agent starting — ID %s, server %s",
            cfg.agent_id, cfg.server_url,
        )

        tasks: list[asyncio.Task] = [
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
        ]

        if cfg.puppet_enabled:
            tasks.append(
                asyncio.create_task(self._puppet_loop(), name="puppet-collector")
            )
        else:
            logger.info(
                "Puppet collector disabled (set PUPPET_ENABLED=true to enable)"
            )

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        cfg = self.config
        consecutive_failures = 0

        while True:
            try:
                async with self._build_client() as client:
                    resp = await client.post(
                        f"/api/v1/agents/{cfg.agent_id}/heartbeat",
                        json={"agent_version": _agent_version()},
                    )
                    resp.raise_for_status()
                    consecutive_failures = 0

                    # Check if the server requires an agent update
                    data = resp.json()
                    if data.get("agent_update_required"):
                        logger.warning(
                            "Server requires agent update (target: %s). Updating…",
                            data.get("agent_update_target"),
                        )
                        await self._self_update(data.get("agent_update_target"))
                        return  # _self_update restarts the process; this is a safety exit

                    logger.debug(
                        "Heartbeat OK (server %s)", data.get("server_version", "?")
                    )
            except httpx.HTTPStatusError as exc:
                consecutive_failures += 1
                logger.warning(
                    "Heartbeat HTTP %s (%d consecutive failure(s))",
                    exc.response.status_code, consecutive_failures,
                )
            except Exception as exc:
                consecutive_failures += 1
                logger.warning(
                    "Heartbeat failed: %s (%d consecutive failure(s))",
                    exc, consecutive_failures,
                )

            await asyncio.sleep(cfg.heartbeat_interval)

    async def _self_update(self, update_target: str | None = None) -> None:
        """Trigger an in-place pip upgrade and restart the agent process."""
        try:
            await asyncio.to_thread(
                _run_self_update, update_target
            )
        except Exception:
            logger.exception(
                "Self-update failed — agent will continue running on the old version"
            )

    # ------------------------------------------------------------------
    # Puppet collector
    # ------------------------------------------------------------------

    async def _puppet_loop(self) -> None:
        cfg = self.config
        logger.info(
            "Puppet collector active — sync every %ds", cfg.puppet_sync_interval
        )

        while True:
            try:
                await asyncio.to_thread(self._run_puppet_sync)
            except Exception:
                logger.exception("Puppet sync failed")
            await asyncio.sleep(cfg.puppet_sync_interval)

    def _run_puppet_sync(self) -> None:
        """Run the Puppet collector synchronously in a thread."""
        cfg = self.config

        # Pass config values to the collector via environment variables
        # so the existing collector code (which uses os.environ) works as-is.
        env_overrides: dict[str, str] = {
            "DKASTLE_SERVER_URL": cfg.server_url,
            "DKASTLE_AGENT_ID": cfg.agent_id,
            "DKASTLE_AGENT_CERT": cfg.agent_cert,
            "DKASTLE_AGENT_KEY": cfg.agent_key,
            "DKASTLE_AGENT_CA": cfg.agent_ca,
            "PUPPET_BATCH_SIZE": str(cfg.puppet_batch_size),
        }
        if cfg.puppet_fact_cache_dir:
            env_overrides["PUPPET_FACT_CACHE_DIR"] = cfg.puppet_fact_cache_dir
        if cfg.puppet_report_dir:
            env_overrides["PUPPET_REPORT_DIR"] = cfg.puppet_report_dir

        original = {k: os.environ.get(k) for k in env_overrides}
        try:
            os.environ.update(env_overrides)
            from agent.collectors.puppet import collect_and_submit
            collect_and_submit()
        finally:
            for k, v in original.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _agent_version() -> str:
    try:
        from importlib.metadata import version
        return version("discoverykastle-agent")
    except Exception:
        return "dev"


def _run_self_update(update_target: str | None) -> None:
    """
    Run in a thread via asyncio.to_thread.
    Imports the updater lazily so it can be patched in tests.
    """
    from agent.updater import self_update
    self_update(update_target)
