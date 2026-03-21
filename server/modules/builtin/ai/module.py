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

The assessment is stored in Vulnerability.details["ai_context"] so it is
visible in the UI and forwarded to Graylog/file logs as a structured field.

Configuration:
  DKASTLE_AI_ENABLED=true
  DKASTLE_ANTHROPIC_API_KEY=sk-ant-...

Extra dep required:
  pip install 'discoverykastle-server[ai]'
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import TYPE_CHECKING, Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability


class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-ai",
        version="1.0.0",
        description=(
            "AI-powered contextual CVE triage. "
            "Uses an LLM only to assess whether a vulnerability's exploitation "
            "prerequisites are actually met on the affected host — something "
            "deterministic rules cannot do."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ENRICHMENT],
        config_schema={
            "ai_enabled": {"type": "boolean", "default": False},
            "anthropic_api_key": {"type": "string", "description": "Anthropic API key"},
        },
        builtin=True,
    )

    # In-memory cache: {cache_key: assessment_text}
    # key = sha256(cve_id + "|" + sorted service profile)
    # Same CVE on hosts with identical service profiles → reuse assessment.
    _cache: dict[str, str] = {}

    # Semaphore: at most 3 concurrent AI calls to avoid hammering the API.
    _sem: asyncio.Semaphore = asyncio.Semaphore(3)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        from server.config import settings

        self._enabled: bool = self.config.get("ai_enabled", settings.ai_enabled)
        self._api_key: str | None = (
            self.config.get("anthropic_api_key") or settings.anthropic_api_key
        )
        self._client: Any = None  # anthropic.AsyncAnthropic — lazy init

    async def setup(self) -> None:
        if not self._enabled:
            self.logger.info(
                "AI enrichment disabled — set DKASTLE_AI_ENABLED=true to enable.",
                extra={"event": "setup", "action": "ai_disabled"},
            )
            return

        if not self._api_key:
            self.logger.warning(
                "AI enrichment enabled but DKASTLE_ANTHROPIC_API_KEY is not set — disabling.",
                extra={"event": "setup", "action": "ai_no_key"},
            )
            self._enabled = False
            return

        try:
            import anthropic  # type: ignore[import-untyped]

            self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
            self.logger.info(
                "AI enrichment active (contextual CVE triage only).",
                extra={"event": "setup", "action": "ai_ready"},
            )
        except ImportError:
            self.logger.warning(
                "DKASTLE_AI_ENABLED=true but 'anthropic' is not installed. "
                "Run: pip install 'discoverykastle-server[ai]'",
                extra={"event": "setup", "action": "ai_missing_dep"},
            )
            self._enabled = False

    async def teardown(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Event hook — called after every new vulnerability is linked to a host
    # ------------------------------------------------------------------

    async def on_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        """
        Enrich the vulnerability with a contextual exploitability assessment.

        This is the ONLY place in the codebase where AI is used.
        The assessment supplements (never replaces) the CVSS-based alert.
        """
        if not self._enabled or self._client is None:
            return

        # Only worth asking about medium+ CVSS — low scores don't justify the API call
        if (vuln.cvss_score or 0.0) < 4.0:
            return

        # Skip if already assessed
        if vuln.details and vuln.details.get("ai_context"):
            return

        t0 = time.monotonic()
        try:
            assessment = await self._assess_vulnerability(vuln, host)
        except Exception:
            self.logger.exception(
                "AI assessment failed for %s on host %s — skipping.",
                vuln.cve_id,
                host.ip_addresses[0] if host.ip_addresses else str(host.id),
                extra={
                    "action": "ai_assess_failed",
                    "cve_id": vuln.cve_id,
                    "host_ip": host.ip_addresses[0] if host.ip_addresses else None,
                },
            )
            return

        # Merge assessment into the vulnerability's details dict
        details = dict(vuln.details or {})
        details["ai_context"] = assessment
        vuln.details = details
        await db.flush()

        self.logger.info(
            "AI contextual assessment for %s: %s",
            vuln.cve_id,
            assessment.get("summary", ""),
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

    async def _assess_vulnerability(
        self, vuln: "Vulnerability", host: "Host"
    ) -> dict[str, Any]:
        """
        Ask Claude Haiku whether this CVE is exploitable in context.

        Returns a dict with:
          exploitable_in_context: bool | null  (null = cannot determine)
          confidence: "high" | "medium" | "low"
          summary: str  (1-2 sentences for the operator)
          prerequisites_met: bool | null  (are the CVE's requirements satisfied?)
        """
        # Build a service profile for cache key and prompt
        service_lines = _describe_services(host)
        cache_key = _cache_key(vuln.cve_id or "", service_lines)

        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = _build_prompt(vuln, host, service_lines)

        async with self._sem:
            response = await self._client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=256,
                system=(
                    "You are a cybersecurity analyst. "
                    "Respond with a single JSON object and nothing else. "
                    "Keys: exploitable_in_context (boolean or null), "
                    "confidence (\"high\"|\"medium\"|\"low\"), "
                    "summary (string, max 2 sentences), "
                    "prerequisites_met (boolean or null)."
                ),
                messages=[{"role": "user", "content": prompt}],
            )

        raw = response.content[0].text.strip()

        import json
        try:
            # Strip markdown code fences if the model wraps in ```json ... ```
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            assessment: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, IndexError):
            assessment = {
                "exploitable_in_context": None,
                "confidence": "low",
                "summary": raw[:300],
                "prerequisites_met": None,
            }

        self._cache[cache_key] = assessment
        return assessment


# ------------------------------------------------------------------
# Helpers (module-level, no state)
# ------------------------------------------------------------------

def _describe_services(host: "Host") -> list[str]:
    """
    Build a compact service description list from the host's known services.
    Falls back to a minimal description if services aren't loaded yet.
    """
    lines: list[str] = []
    services = getattr(host, "services", None) or []
    for svc in services:
        port = getattr(svc, "port", None)
        proto = getattr(svc, "protocol", "tcp")
        name = getattr(svc, "service_name", "") or ""
        version = getattr(svc, "version", "") or ""
        parts = [f"{port}/{proto}"]
        if name:
            parts.append(name)
        if version:
            parts.append(version)
        lines.append(" ".join(parts))
    return lines


def _cache_key(cve_id: str, service_lines: list[str]) -> str:
    payload = cve_id + "|" + ",".join(sorted(service_lines))
    return hashlib.sha256(payload.encode()).hexdigest()


def _build_prompt(
    vuln: "Vulnerability",
    host: "Host",
    service_lines: list[str],
) -> str:
    host_label = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else "unknown")
    os_info = f"{host.os or 'unknown'} {host.os_version or ''}".strip()
    services_text = (
        "\n".join(f"  - {s}" for s in service_lines)
        if service_lines
        else "  (no exposed services detected yet)"
    )

    description = (vuln.description or "No description available.")[:800]

    return (
        f"CVE: {vuln.cve_id}\n"
        f"CVSS score: {vuln.cvss_score}\n"
        f"Description: {description}\n"
        f"\n"
        f"Affected host: {host_label}\n"
        f"Operating system: {os_info}\n"
        f"Exposed services (port/proto name version):\n{services_text}\n"
        f"\n"
        f"Question: Based on the CVE description's exploitation prerequisites, "
        f"is this vulnerability actually exploitable on this specific host given "
        f"its exposed services? Consider whether the required service, protocol, "
        f"or access path is present."
    )
