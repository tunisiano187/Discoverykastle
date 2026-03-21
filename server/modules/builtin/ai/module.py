"""
Built-in AI Enrichment module.

─────────────────────────────────────────────────────────────────────────────
USAGE POLICY — Read before enabling
─────────────────────────────────────────────────────────────────────────────

AI is used HERE AND ONLY HERE in the entire platform, and only for ONE task:

  Contextual CVE exploitability triage.

Why can't rules do this?
  A CVE like Log4Shell (CVSS 10.0) requires a Java application using Log4j
  to process user-controlled input AND outbound network access to an attacker-
  controlled LDAP server.  If the affected host only exposes SSH and PostgreSQL,
  the actual exploitability is far lower than the raw CVSS score suggests.
  No deterministic rule can read a CVE description and understand its
  exploitation prerequisites — that requires natural language understanding.

What this module does NOT do:
  • It does not replace CVSS-based alert thresholds (those stay in builtin-alerts).
  • It does not build network topology (graph algorithms do that).
  • It does not deduplicate data (handled deterministically).
  • It does not replace any logic that can be expressed as a rule.

─────────────────────────────────────────────────────────────────────────────
ADDING A NEW BACKEND
─────────────────────────────────────────────────────────────────────────────
See server/modules/builtin/ai/backends/__init__.py for full instructions.
Short version:

    from server.modules.builtin.ai.backends import _Backend, register

    @register("mybackend")
    class MyBackend(_Backend):
        label = "My Backend"
        async def probe(self) -> bool: ...
        async def complete(self, system, user) -> str: ...

Set DKASTLE_AI_BACKEND=mybackend and it will be picked up automatically.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability
    from server.modules.builtin.ai.backends.base import _Backend

_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. "
    "Respond with a single JSON object and nothing else. "
    "Keys: exploitable_in_context (boolean or null), "
    "confidence (\"high\"|\"medium\"|\"low\"), "
    "summary (string, max 2 sentences), "
    "prerequisites_met (boolean or null)."
)


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-ai",
        version="2.0.0",
        description=(
            "AI-powered contextual CVE triage. Uses an LLM only to assess whether a "
            "vulnerability's exploitation prerequisites are met on the affected host. "
            "Supports pluggable backends: Ollama (local, recommended), Anthropic, "
            "or any custom backend registered in the backends/ package."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ENRICHMENT],
        config_schema={
            "ai_enabled":        {"type": "boolean", "default": False},
            "ai_backend":        {"type": "string",  "default": "auto",
                                  "description": "auto | ollama | anthropic | <custom>"},
            "ollama_url":        {"type": "string",  "default": "http://localhost:11434"},
            "ollama_model":      {"type": "string",  "default": "llama3.2"},
            "anthropic_api_key": {"type": "string"},
            "anthropic_model":   {"type": "string",  "default": "claude-haiku-4-5-20251001"},
        },
        builtin=True,
    )

    _cache: dict[str, dict[str, Any]] = {}
    _sem: asyncio.Semaphore = asyncio.Semaphore(3)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        from server.config import settings

        self._enabled: bool = self.config.get("ai_enabled", settings.ai_enabled)
        self._backend_name: str = (
            self.config.get("ai_backend", settings.ai_backend) or "auto"
        ).lower()
        self._ollama_url: str   = self.config.get("ollama_url",   settings.ollama_url)
        self._ollama_model: str = self.config.get("ollama_model", settings.ollama_model)
        self._anthropic_key: str | None = (
            self.config.get("anthropic_api_key") or settings.anthropic_api_key
        )
        self._anthropic_model: str = self.config.get(
            "anthropic_model", settings.anthropic_model
        )
        self._backend: "_Backend | None" = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        if not self._enabled:
            self.logger.info(
                "AI enrichment disabled — set DKASTLE_AI_ENABLED=true to enable.",
                extra={"event": "setup", "action": "ai_disabled"},
            )
            return

        self._backend = await self._resolve_backend()
        if self._backend is None:
            self._enabled = False

    async def teardown(self) -> None:
        if self._backend is not None:
            try:
                await self._backend.close()
            except Exception:
                pass

    async def _resolve_backend(self) -> "_Backend | None":
        """
        Resolve DKASTLE_AI_BACKEND to a live backend instance.

        - Named backend  → instantiate directly, probe, return.
        - "auto"         → try each registered backend in preference order
                           (Ollama first since it's local and free), return
                           the first one that responds to probe().
        """
        from server.modules.builtin.ai.backends import REGISTRY

        if self._backend_name == "auto":
            # Preference order: ollama first (local, no cost), then others
            ordered = ["ollama"] + [k for k in REGISTRY if k != "ollama"]
            for name in ordered:
                backend = await self._try_init(name, REGISTRY)
                if backend is not None:
                    return backend
            self.logger.warning(
                "AI backend 'auto': no backend is available. "
                "Start Ollama or set DKASTLE_ANTHROPIC_API_KEY.",
                extra={"event": "setup", "action": "ai_no_backend"},
            )
            return None

        backend = await self._try_init(self._backend_name, REGISTRY)
        if backend is None:
            self.logger.warning(
                "AI backend '%s' is not available — AI enrichment disabled.",
                self._backend_name,
                extra={"event": "setup", "action": "ai_backend_unavailable",
                       "ai_backend": self._backend_name},
            )
        return backend

    async def _try_init(self, name: str, registry: dict) -> "_Backend | None":
        """Instantiate, probe, and return a backend, or None on any failure."""
        cls = registry.get(name)
        if cls is None:
            self.logger.warning(
                "Unknown AI backend '%s'. Available: %s",
                name, list(registry.keys()),
                extra={"event": "setup", "action": "ai_unknown_backend",
                       "ai_backend": name},
            )
            return None

        try:
            backend = self._instantiate(name, cls)
        except ImportError as exc:
            self.logger.warning(
                "Backend '%s' requires an extra dependency: %s",
                name, exc,
                extra={"event": "setup", "action": "ai_missing_dep",
                       "ai_backend": name},
            )
            return None
        except Exception as exc:
            self.logger.warning(
                "Backend '%s' failed to initialise: %s",
                name, exc,
                extra={"event": "setup", "action": "ai_init_error",
                       "ai_backend": name},
            )
            return None

        if not await backend.probe():
            return None

        self.logger.info(
            "AI enrichment active — backend: %s (%s)",
            name, backend.label,
            extra={"event": "setup", "action": "ai_ready", "ai_backend": name},
        )
        return backend

    def _instantiate(self, name: str, cls: type) -> "_Backend":
        """Build a backend instance with the appropriate config kwargs."""
        if name == "ollama":
            return cls(url=self._ollama_url, model=self._ollama_model)
        if name == "anthropic":
            if not self._anthropic_key:
                raise ValueError(
                    "DKASTLE_ANTHROPIC_API_KEY is required for the Anthropic backend."
                )
            return cls(api_key=self._anthropic_key, model=self._anthropic_model)
        # Custom / third-party backends — instantiate with no args;
        # they should read their own config from settings or env.
        return cls()

    # ------------------------------------------------------------------
    # Event hook
    # ------------------------------------------------------------------

    async def on_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        if not self._enabled or self._backend is None:
            return
        if (vuln.cvss_score or 0.0) < 4.0:
            return
        if vuln.details and vuln.details.get("ai_context"):
            return

        t0 = time.monotonic()
        try:
            assessment = await self._assess(vuln, host)
        except Exception:
            self.logger.exception(
                "AI assessment failed for %s — skipping.",
                vuln.cve_id,
                extra={"action": "ai_assess_failed", "cve_id": vuln.cve_id,
                       "host_ip": host.ip_addresses[0] if host.ip_addresses else None},
            )
            return

        details = dict(vuln.details or {})
        details["ai_context"] = assessment
        vuln.details = details
        await db.flush()

        self.logger.info(
            "AI contextual assessment for %s: %s",
            vuln.cve_id, assessment.get("summary", ""),
            extra={
                "action": "ai_assess_done",
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "host_ip": host.ip_addresses[0] if host.ip_addresses else None,
                "host_fqdn": host.fqdn,
                "exploitable_in_context": assessment.get("exploitable_in_context"),
                "confidence": assessment.get("confidence"),
                "duration_ms": round((time.monotonic() - t0) * 1000),
            },
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _assess(self, vuln: "Vulnerability", host: "Host") -> dict[str, Any]:
        service_lines = _describe_services(host)
        key = _cache_key(vuln.cve_id or "", service_lines)
        if key in self._cache:
            return self._cache[key]

        async with self._sem:
            raw = await self._backend.complete(_SYSTEM_PROMPT, _build_prompt(vuln, host, service_lines))  # type: ignore[union-attr]

        raw = raw.strip()
        try:
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            result: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, IndexError):
            result = {"exploitable_in_context": None, "confidence": "low",
                      "summary": raw[:300], "prerequisites_met": None}

        self._cache[key] = result
        return result


# ──────────────────────────────────────────────────────────────────────────────
# Pure helpers
# ──────────────────────────────────────────────────────────────────────────────

def _describe_services(host: "Host") -> list[str]:
    lines = []
    for svc in (getattr(host, "services", None) or []):
        parts = [f"{getattr(svc, 'port', '?')}/{getattr(svc, 'protocol', 'tcp')}"]
        if name := (getattr(svc, "service_name", "") or ""):
            parts.append(name)
        if ver := (getattr(svc, "version", "") or ""):
            parts.append(ver)
        lines.append(" ".join(parts))
    return lines


def _cache_key(cve_id: str, service_lines: list[str]) -> str:
    return hashlib.sha256((cve_id + "|" + ",".join(sorted(service_lines))).encode()).hexdigest()


def _build_prompt(vuln: "Vulnerability", host: "Host", service_lines: list[str]) -> str:
    label    = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else "unknown")
    os_info  = f"{host.os or 'unknown'} {host.os_version or ''}".strip()
    svc_text = (
        "\n".join(f"  - {s}" for s in service_lines)
        if service_lines else "  (no exposed services detected yet)"
    )
    return (
        f"CVE: {vuln.cve_id}\nCVSS score: {vuln.cvss_score}\n"
        f"Description: {(vuln.description or 'No description.')[:800]}\n\n"
        f"Affected host: {label}\nOperating system: {os_info}\n"
        f"Exposed services:\n{svc_text}\n\n"
        f"Question: Based on this CVE's exploitation prerequisites, is it actually "
        f"exploitable on this host given its exposed services?"
    )
