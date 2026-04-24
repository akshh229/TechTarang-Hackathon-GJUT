from typing import Any

from .base_adapter import LLMProviderAdapter


class GeminiAdapter(LLMProviderAdapter):
    """Prototype stub for Google Gemini."""

    async def complete(self, system_prompt: str, user_message: str, **kwargs: Any) -> str:
        return (
            "[Gemini stub] Multimodal guardrails remained active. "
            f"Prompt summary: {user_message[:180]}"
        )
