from __future__ import annotations

from typing import Any, Dict, List, Optional

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


class PolicyRecommendationItem(BaseModel):
    rule_type: str = Field(default="semantic_signal")
    description: str = Field(default="")
    proposed_value: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence_count: int = Field(default=0, ge=0)
    impact: str = Field(default="MEDIUM")
    safe_to_auto_apply: bool = Field(default=False)


class PolicyRecommendationResult(BaseModel):
    recommendations: List[PolicyRecommendationItem] = Field(default_factory=list)
    false_positive_candidates: List[str] = Field(default_factory=list)
    summary: str = Field(default="")
    digest: Optional[Dict[str, Any]] = Field(default=None)
    generated_at: Optional[str] = Field(default=None)


class EgressClassificationResult(BaseModel):
    label: str = Field(default="PASS")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    risk_reasons: List[str] = Field(default_factory=list)
    redact_spans: List[str] = Field(default_factory=list)
    recommended_action: str = Field(default="allow")
    was_classified: bool = Field(default=False)
