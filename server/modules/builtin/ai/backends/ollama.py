"""
Ollama backend — local inference, no API key, no extra pip dependency.

Install:  https://ollama.com/download
Start:    ollama serve
Models:   ollama pull llama3.2        (default — fast, good reasoning)
          ollama pull mistral
          ollama pull phi3:mini        (CPU-friendly)
          ollama pull deepseek-r1:7b   (strong security analysis)
          ollama pull qwen2.5:7b

Uses the native /api/chat endpoint with format="json" so the model is
forced to output valid JSON regardless of the system prompt wording.
httpx is already a platform dependency — no extra install required.
"""

from __future__ import annotations

from server.modules.builtin.ai.backends.base import _Backend, register


@register("ollama")
class OllamaBackend(_Backend):

    label = "Ollama (local)"
    requires_key = False

    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.2") -> None:
        self._base = url.rstrip("/")
        self._model = model
        import httpx
        self._client = httpx.AsyncClient(timeout=60)

    async def probe(self) -> bool:
        """Return True if the Ollama daemon is running and reachable."""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                r = await c.get(self._base + "/api/tags")
                return r.is_success
        except Exception:
            return False

    async def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self._model,
            "stream": False,
            "format": "json",  # forces valid JSON output
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }
        r = await self._client.post(self._base + "/api/chat", json=payload)
        r.raise_for_status()
        return r.json()["message"]["content"]

    async def close(self) -> None:
        await self._client.aclose()
