from abc import ABC, abstractmethod
from typing import Any, Dict

class LLMProviderAdapter(ABC):
    """
    Abstract Base Class for LLM Provider Adapters.
    Every provider (OpenAI, Claude, Gemini, etc.) must implement this interface.
    """
    
    @abstractmethod
    async def complete(self, system_prompt: str, user_message: str, **kwargs) -> str:
        """
        Sends a completion request to the LLM provider.
        
        Args:
            system_prompt (str): The system prompt/instructions.
            user_message (str): The user's input/query.
            **kwargs: Additional provider-specific parameters (e.g., temperature).
            
        Returns:
            str: The raw text response from the LLM.
        """
        raise NotImplementedError("Subclasses must implement the 'complete' method.")
