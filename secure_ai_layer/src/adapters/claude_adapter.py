from typing import Any

from .base_adapter import LLMProviderAdapter


class ClaudeAdapter(LLMProviderAdapter):
    """Prototype stub for Anthropic Claude."""

    async def complete(self, system_prompt: str, user_message: str, **kwargs: Any) -> str:
        return (
            "[Claude stub] Secure middleware accepted the request after ingress screening. "
            f"Prompt summary: {user_message[:180]}"
        )
