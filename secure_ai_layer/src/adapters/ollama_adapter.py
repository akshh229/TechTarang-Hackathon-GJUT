from typing import Any

from .base_adapter import LLMProviderAdapter


class OllamaAdapter(LLMProviderAdapter):
    """Prototype stub for local LLM providers."""

    async def complete(self, system_prompt: str, user_message: str, **kwargs: Any) -> str:
        return (
            "[Ollama stub] Local provider execution is stubbed for the hackathon demo. "
            f"Prompt summary: {user_message[:180]}"
        )
