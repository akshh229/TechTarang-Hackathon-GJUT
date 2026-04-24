from __future__ import annotations

from typing import Any, Dict, Iterable

from src.adapters.factory import get_provider_adapter
from src.ai.client import complete_json
from src.ai.schemas import IntentClassificationResult


INTENT_CLASSIFIER_SYSTEM_PROMPT = """
You classify secure banking-assistant requests into one approved intent.
Return strict JSON only with keys:
- intent
- confidence
- extracted_entities
- rationale

Rules:
- Choose only from the allowed intents provided.
- If the request is ambiguous, choose UNKNOWN_INTENT.
- Keep confidence conservative.
- extracted_entities must be a flat JSON object with string values only.
""".strip()


class IntentClassifier:
    def __init__(self, min_confidence: float = 0.7):
        self.min_confidence = min_confidence

    async def classify(
        self,
        message: str,
        allowed_intents: Iterable[str],
        *,
        provider_override: str | None = None,
        model: str | None = None,
    ) -> IntentClassificationResult:
        provider_name, adapter = get_provider_adapter(provider_override)
        allowed = sorted(set(allowed_intents))
        prompt = (
            f"Allowed intents: {allowed}\n"
            f"User request: {message}\n"
            "Return JSON only."
        )
        result = await complete_json(
            adapter,
            system_prompt=INTENT_CLASSIFIER_SYSTEM_PROMPT,
            user_message=prompt,
            schema=IntentClassificationResult,
            model=model,
            temperature=0,
        )
        if result.intent not in allowed and result.intent != "UNKNOWN_INTENT":
            raise ValueError(f"Disallowed intent from provider {provider_name}: {result.intent}")
        return result

    @staticmethod
    def from_config(config: Dict[str, Any]) -> "IntentClassifier":
        section = config.get("intent_classifier", {})
        return IntentClassifier(min_confidence=float(section.get("min_confidence", 0.7)))
