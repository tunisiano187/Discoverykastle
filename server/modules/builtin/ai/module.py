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

─────────────────────────────────────────────────────────────────────────────
BACKENDS
─────────────────────────────────────────────────────────────────────────────

Two backends are supported and selected via DKASTLE_AI_BACKEND:

  ollama    — Local inference via Ollama (http://localhost:11434).
              No API key. No extra pip dependency (uses httpx).
              Model set via DKASTLE_OLLAMA_MODEL (default: llama3.2).
              Recommended for air-gapped / privacy-sensitive environments.

  anthropic — Anthropic cloud (Claude Haiku by default).
              Requires DKASTLE_ANTHROPIC_API_KEY and:
              pip install 'discoverykastle-server[ai]'

  auto      — Use Ollama if DKASTLE_OLLAMA_URL is reachable, else Anthropic.

─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import abc
import asyncio
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

from server.modules.base import BaseModule, ModuleCapability, ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from server.models import Host, Vulnerability

# System prompt shared by both backends
_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. "
    "Respond with a single JSON object and nothing else. "
    "Keys: exploitable_in_context (boolean or null), "
    "confidence (\"high\"|\"medium\"|\"low\"), "
    "summary (string, max 2 sentences), "
    "prerequisites_met (boolean or null)."
)


# ──────────────────────────────────────────────────────────────────────────────
# Backend protocol + implementations
# ──────────────────────────────────────────────────────────────────────────────

class _Backend(abc.ABC):
    """Minimal interface that each backend must implement."""

    @abc.abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """Send a prompt and return the raw text response."""

    async def close(self) -> None:
        """Release resources if needed."""


class _OllamaBackend(_Backend):
    """
    Calls the local Ollama REST API.

    Endpoint: POST {ollama_url}/api/chat
    Uses format="json" to force structured JSON output.
    No extra pip dependency — httpx is already required by the platform.
    """

    def __init__(self, url: str, model: str) -> None:
        self._url = url.rstrip("/") + "/api/chat"
        self._model = model
        # Lazy import — httpx is always available
        import httpx
        self._client = httpx.AsyncClient(timeout=60)

    async def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self._model,
            "stream": False,
            "format": "json",  # Ollama guarantees valid JSON output
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }
        response = await self._client.post(self._url, json=payload)
        response.raise_for_status()
        return response.json()["message"]["content"]

    async def close(self) -> None:
        await self._client.aclose()


class _AnthropicBackend(_Backend):
    """
    Calls the Anthropic cloud API via the official SDK.

    Requires: pip install 'discoverykastle-server[ai]'
    """

    def __init__(self, api_key: str, model: str) -> None:
        import anthropic  # type: ignore[import-untyped]
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def complete(self, system: str, user: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=256,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    async def close(self) -> None:
        await self._client.close()


# ──────────────────────────────────────────────────────────────────────────────
# Module
# ──────────────────────────────────────────────────────────────────────────────

class Module(BaseModule):
    manifest = ModuleManifest(
        name="builtin-ai",
        version="1.1.0",
        description=(
            "AI-powered contextual CVE triage. "
            "Uses an LLM only to assess whether a vulnerability's exploitation "
            "prerequisites are actually met on the affected host — something "
            "deterministic rules cannot do. "
            "Supports Ollama (local) and Anthropic (cloud)."
        ),
        author="Discoverykastle",
        capabilities=[ModuleCapability.ENRICHMENT],
        config_schema={
            "ai_enabled":         {"type": "boolean", "default": False},
            "ai_backend":         {"type": "string",  "default": "auto",
                                   "enum": ["auto", "ollama", "anthropic"]},
            "ollama_url":         {"type": "string",  "default": "http://localhost:11434"},
            "ollama_model":       {"type": "string",  "default": "llama3.2"},
            "anthropic_api_key":  {"type": "string"},
            "anthropic_model":    {"type": "string",  "default": "claude-haiku-4-5-20251001"},
        },
        builtin=True,
    )

    # In-memory result cache: sha256(cve_id + service_profile) → assessment dict
    # Same CVE on hosts with identical service profiles reuses the result.
    _cache: dict[str, dict[str, Any]] = {}

    # At most 3 concurrent LLM calls regardless of backend.
    _sem: asyncio.Semaphore = asyncio.Semaphore(3)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        from server.config import settings

        self._enabled: bool  = self.config.get("ai_enabled",  settings.ai_enabled)
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
        self._backend: _Backend | None = None

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

        self._backend = await self._init_backend()
        if self._backend is None:
            self._enabled = False

    async def teardown(self) -> None:
        if self._backend is not None:
            try:
                await self._backend.close()
            except Exception:
                pass

    async def _init_backend(self) -> _Backend | None:
        """
        Initialise and validate the configured backend.
        Returns None (with a warning) if the backend cannot be set up.
        """
        want = self._backend_name

        if want in ("auto", "ollama"):
            backend = await self._try_ollama()
            if backend is not None:
                return backend
            if want == "ollama":
                # Explicitly requested but unavailable — don't fall through
                self.logger.warning(
                    "AI backend 'ollama' requested but Ollama is not reachable at %s. "
                    "Is Ollama running? Start it with: ollama serve",
                    self._ollama_url,
                    extra={"event": "setup", "action": "ai_ollama_unreachable",
                           "ollama_url": self._ollama_url},
                )
                return None
            # auto: fall through to Anthropic
            self.logger.info(
                "Ollama not reachable — falling back to Anthropic backend.",
                extra={"event": "setup", "action": "ai_fallback_anthropic"},
            )

        if want in ("auto", "anthropic"):
            return self._try_anthropic()

        self.logger.warning(
            "Unknown DKASTLE_AI_BACKEND value '%s' — expected auto|ollama|anthropic.",
            want,
            extra={"event": "setup", "action": "ai_bad_backend"},
        )
        return None

    async def _try_ollama(self) -> _Backend | None:
        """
        Probe Ollama with a lightweight GET /api/tags.
        Returns a ready backend, or None if Ollama is not available.
        """
        import httpx

        try:
            async with httpx.AsyncClient(timeout=3) as probe:
                r = await probe.get(self._ollama_url.rstrip("/") + "/api/tags")
                r.raise_for_status()
        except Exception:
            return None

        backend = _OllamaBackend(self._ollama_url, self._ollama_model)
        self.logger.info(
            "AI enrichment active — backend: Ollama, model: %s, url: %s",
            self._ollama_model, self._ollama_url,
            extra={
                "event": "setup", "action": "ai_ready",
                "ai_backend": "ollama",
                "ollama_model": self._ollama_model,
                "ollama_url": self._ollama_url,
            },
        )
        return backend

    def _try_anthropic(self) -> _Backend | None:
        """Initialise the Anthropic SDK backend."""
        if not self._anthropic_key:
            self.logger.warning(
                "AI backend 'anthropic' selected but DKASTLE_ANTHROPIC_API_KEY is not set.",
                extra={"event": "setup", "action": "ai_no_key"},
            )
            return None
        try:
            backend = _AnthropicBackend(self._anthropic_key, self._anthropic_model)
            self.logger.info(
                "AI enrichment active — backend: Anthropic, model: %s",
                self._anthropic_model,
                extra={
                    "event": "setup", "action": "ai_ready",
                    "ai_backend": "anthropic",
                    "anthropic_model": self._anthropic_model,
                },
            )
            return backend
        except ImportError:
            self.logger.warning(
                "AI backend 'anthropic' selected but the SDK is not installed. "
                "Run: pip install 'discoverykastle-server[ai]'",
                extra={"event": "setup", "action": "ai_missing_dep"},
            )
            return None

    # ------------------------------------------------------------------
    # Event hook
    # ------------------------------------------------------------------

    async def on_vulnerability_found(
        self, vuln: "Vulnerability", host: "Host", db: "AsyncSession"
    ) -> None:
        """
        Enrich the vulnerability with a contextual exploitability assessment.

        This is the ONLY place in the codebase where AI is used.
        The assessment supplements (never replaces) the CVSS-based alert.
        """
        if not self._enabled or self._backend is None:
            return

        # Only worth calling the LLM for medium+ severity
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
        service_lines = _describe_services(host)
        cache_key = _cache_key(vuln.cve_id or "", service_lines)

        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = _build_prompt(vuln, host, service_lines)

        async with self._sem:
            raw = await self._backend.complete(_SYSTEM_PROMPT, prompt)  # type: ignore[union-attr]

        raw = raw.strip()
        try:
            # Strip markdown code fences if the model wraps output in ```json ... ```
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


# ──────────────────────────────────────────────────────────────────────────────
# Pure helpers (no state, no imports from models at module load time)
# ──────────────────────────────────────────────────────────────────────────────

def _describe_services(host: "Host") -> list[str]:
    lines: list[str] = []
    for svc in (getattr(host, "services", None) or []):
        parts = [f"{getattr(svc, 'port', '?')}/{getattr(svc, 'protocol', 'tcp')}"]
        name    = getattr(svc, "service_name", "") or ""
        version = getattr(svc, "version", "")      or ""
        if name:
            parts.append(name)
        if version:
            parts.append(version)
        lines.append(" ".join(parts))
    return lines


def _cache_key(cve_id: str, service_lines: list[str]) -> str:
    payload = cve_id + "|" + ",".join(sorted(service_lines))
    return hashlib.sha256(payload.encode()).hexdigest()


def _build_prompt(vuln: "Vulnerability", host: "Host", service_lines: list[str]) -> str:
    host_label   = host.fqdn or (host.ip_addresses[0] if host.ip_addresses else "unknown")
    os_info      = f"{host.os or 'unknown'} {host.os_version or ''}".strip()
    services_txt = (
        "\n".join(f"  - {s}" for s in service_lines)
        if service_lines else "  (no exposed services detected yet)"
    )
    description  = (vuln.description or "No description available.")[:800]

    return (
        f"CVE: {vuln.cve_id}\n"
        f"CVSS score: {vuln.cvss_score}\n"
        f"Description: {description}\n"
        f"\n"
        f"Affected host: {host_label}\n"
        f"Operating system: {os_info}\n"
        f"Exposed services (port/proto name version):\n{services_txt}\n"
        f"\n"
        f"Question: Based on the CVE description's exploitation prerequisites, "
        f"is this vulnerability actually exploitable on this specific host given "
        f"its exposed services? Consider whether the required service, protocol, "
        f"or access path is present."
    )
