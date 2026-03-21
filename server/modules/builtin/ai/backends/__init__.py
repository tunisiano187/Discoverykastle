"""
AI backend registry.

Adding a new backend
────────────────────
1. Create a new file in this directory (e.g. openai.py).
2. Subclass _Backend and decorate with @register("your-name").
3. That's it — the backend is automatically available via DKASTLE_AI_BACKEND.

Example skeleton:

    from server.modules.builtin.ai.backends import _Backend, register

    @register("openai")
    class OpenAIBackend(_Backend):
        name = "openai"
        label = "OpenAI"
        requires_key = True          # set False if no API key needed
        key_env = "DKASTLE_OPENAI_API_KEY"

        def __init__(self, **kwargs):
            self._model = kwargs.get("model", "gpt-4o-mini")
            ...

        async def complete(self, system: str, user: str) -> str:
            ...

        async def probe(self) -> bool:
            # Return True if this backend is available right now.
            ...
"""

from server.modules.builtin.ai.backends.base import _Backend, register, REGISTRY

# Import built-in backends so they self-register via @register(...)
from server.modules.builtin.ai.backends import ollama      # noqa: F401
from server.modules.builtin.ai.backends import anthropic_  # noqa: F401

__all__ = ["_Backend", "register", "REGISTRY"]
