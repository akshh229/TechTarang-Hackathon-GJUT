from typing import Tuple

from src.config.config_loader import get_policy_config

from .claude_adapter import ClaudeAdapter
from .gemini_adapter import GeminiAdapter
from .ollama_adapter import OllamaAdapter
from .openai_adapter import OpenAIAdapter
from .base_adapter import LLMProviderAdapter


def get_provider_adapter(provider_override: str | None = None) -> Tuple[str, LLMProviderAdapter]:
    config = get_policy_config()
    provider = (provider_override or config.get("llm", {}).get("provider", "openai")).lower()

    adapters = {
        "openai": OpenAIAdapter,
        "claude": ClaudeAdapter,
        "gemini": GeminiAdapter,
        "ollama": OllamaAdapter,
    }

    adapter_cls = adapters.get(provider, OpenAIAdapter)
    resolved_provider = provider if provider in adapters else "openai"
    return resolved_provider, adapter_cls()
