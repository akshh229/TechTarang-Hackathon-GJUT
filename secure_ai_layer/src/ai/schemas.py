from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field


class IntentClassificationResult(BaseModel):
    intent: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    extracted_entities: Dict[str, str] = Field(default_factory=dict)
    rationale: str = Field(default="")


class BlockExplanationResult(BaseModel):
    user_reason: str = Field(min_length=1)
    operator_reason: str = Field(min_length=1)
    safe_rewrite: str = Field(default="")
    families: List[str] = Field(default_factory=list)
