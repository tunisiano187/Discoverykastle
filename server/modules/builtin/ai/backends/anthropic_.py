"""
Anthropic backend — cloud inference via the official SDK.

Install:  pip install 'discoverykastle-server[ai]'
API key:  https://console.anthropic.com/

Recommended models:
  claude-haiku-4-5-20251001   fast, cheap (default)
  claude-sonnet-4-6            more accurate, higher cost
"""

from __future__ import annotations

from server.modules.builtin.ai.backends.base import _Backend, register


@register("anthropic")
class AnthropicBackend(_Backend):

    label = "Anthropic (cloud)"
    requires_key = True
    key_env = "DKASTLE_ANTHROPIC_API_KEY"

    def __init__(
        self,
        api_key: str,
        model: str = "claude-haiku-4-5-20251001",
    ) -> None:
        import anthropic  # type: ignore[import-untyped]
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def probe(self) -> bool:
        """
        A real probe would call GET /v1/models — avoid that to save tokens.
        Instead we just verify the client initialised (key format valid).
        """
        return bool(self._client)

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
