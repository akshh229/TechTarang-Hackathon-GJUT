from __future__ import annotations

import json
from typing import Any, Type

from pydantic import BaseModel, ValidationError

from src.adapters.base_adapter import LLMProviderAdapter


def _extract_json_object(raw_text: str) -> str | None:
    if not raw_text:
        return None

    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = [line for line in cleaned.splitlines() if not line.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return cleaned[start : end + 1]


async def complete_json(
    adapter: LLMProviderAdapter,
    *,
    system_prompt: str,
    user_message: str,
    schema: Type[BaseModel],
    **kwargs: Any,
) -> BaseModel:
    raw_response = await adapter.complete(system_prompt, user_message, **kwargs)
    json_blob = _extract_json_object(raw_response)
    if not json_blob:
        raise ValueError("Provider did not return a JSON object.")

    try:
        payload = json.loads(json_blob)
    except json.JSONDecodeError as exc:
        raise ValueError("Provider returned invalid JSON.") from exc

    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        raise ValueError("Provider JSON did not match the expected schema.") from exc
