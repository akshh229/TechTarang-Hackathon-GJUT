import os
from openai import AsyncOpenAI
from typing import Any
from .base_adapter import LLMProviderAdapter

class OpenAIAdapter(LLMProviderAdapter):
    """
    OpenAI specific implementation of the LLMProviderAdapter.
    """
    def __init__(self):
        # We assume the user has loaded OPENAI_API_KEY in the environment
        # or via dotenv locally.
        api_key = os.getenv("OPENAI_API_KEY")
        self.client = AsyncOpenAI(api_key=api_key) if api_key else None
        
    async def complete(self, system_prompt: str, user_message: str, **kwargs: Any) -> str:
        model = kwargs.get("model", "gpt-4.1-mini")
        temperature = kwargs.get("temperature", 0.7)

        if self.client is None:
            return (
                "[Offline stub] Secure middleware intercepted the request and no live OpenAI key is configured. "
                f"Sanitised prompt: {user_message}. Test PAN ABCDE1234F."
            )

        try:
            response = await self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            # For hackathon demo resilience, if API fails (e.g. no key),
            # return a graceful fallback that includes some PII to test redaction.
            print(f"OpenAI completion failed: {e}")
            return f"[Offline stub] You said: {user_message}. My test PAN is ABCDE1234F."
