"""
Unstructured Egress Leak Classifier – Stage 2 of the egress pipeline.

Stage 1 (EgressRedactor) handles structured PII via regex.
Stage 2 (this module) uses an AI model to catch:
  - hardcoded credentials and API keys
  - internal system-prompt fragments
  - sensitive narrative content (financial projections, PII-in-prose)
  - policy-violating summarizations of internal data

Only invoked when risk mode warrants it (configurable threshold in policy.yaml).
Falls back to deterministic label "PASS" if the model call fails.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.adapters.factory import get_provider_adapter
from src.ai.client import complete_json
from src.ai.schemas import EgressClassificationResult


EGRESS_CLASSIFIER_SYSTEM_PROMPT = """
You are a data-loss-prevention (DLP) classifier for an enterprise AI system.
Examine the supplied text output and classify it for potential data leakage.

Return strict JSON only with the following keys:
- label           ("PASS" | "SENSITIVE" | "SECRET_LIKE" | "POLICY_VIOLATING" | "NEEDS_REVIEW")
- confidence      (float 0..1)
- risk_reasons    (list of strings explaining why the text is risky, or empty if PASS)
- redact_spans    (list of strings – verbatim spans that should be redacted; empty if PASS)
- recommended_action ("allow" | "redact" | "block" | "human_review")

Classification guide:
- PASS            : no sensitive content detected
- SENSITIVE       : personal details, financial figures, internal project names
- SECRET_LIKE     : tokens, passwords, API keys, bearer tokens, private keys
- POLICY_VIOLATING: instructions or data that violates the system's output policy
- NEEDS_REVIEW    : borderline; route to human operator

Rules:
- Be conservative; prefer NEEDS_REVIEW over PASS when uncertain.
- redact_spans must be exact verbatim substrings of the input text (never paraphrase).
- Do NOT include the text itself in your answer, only the classification metadata.
""".strip()


# Threshold below which we skip AI classification (too low-risk to justify latency)
_DEFAULT_RISK_THRESHOLD = 20  # threat_score


class EgressClassifier:
    """
    Second-stage egress classifier.
    Should be called AFTER EgressRedactor to catch unstructured leaks.
    """

    async def classify(
        self,
        text: str,
        *,
        threat_score: int = 0,
        risk_level: str = "GREEN",
        provider_override: Optional[str] = None,
        model: Optional[str] = None,
        risk_threshold: int = _DEFAULT_RISK_THRESHOLD,
    ) -> EgressClassificationResult:
        """
        Classify egress text for data leakage.

        Short-circuits to PASS (no AI call) when:
          - text is blank
          - threat_score is below the risk_threshold AND risk_level is GREEN
        """
        if not text or not text.strip():
            return EgressClassificationResult(
                label="PASS",
                confidence=1.0,
                risk_reasons=[],
                redact_spans=[],
                recommended_action="allow",
                was_classified=False,
            )

        # Skip classification for clearly clean responses
        if threat_score < risk_threshold and risk_level == "GREEN":
            return EgressClassificationResult(
                label="PASS",
                confidence=0.9,
                risk_reasons=[],
                redact_spans=[],
                recommended_action="allow",
                was_classified=False,
            )

        _, adapter = get_provider_adapter(provider_override)
        prompt = (
            f"Text to classify (max 4000 chars):\n{text[:4000]}\n\n"
            f"Context: threat_score={threat_score}, risk_level={risk_level}\n"
            "Return JSON only."
        )

        try:
            result = await complete_json(
                adapter,
                system_prompt=EGRESS_CLASSIFIER_SYSTEM_PROMPT,
                user_message=prompt,
                schema=EgressClassificationResult,
                model=model,
                temperature=0,
            )
            result.was_classified = True
            return result
        except Exception:
            # Safe fallback: treat as NEEDS_REVIEW so a human can inspect
            return EgressClassificationResult(
                label="NEEDS_REVIEW",
                confidence=0.0,
                risk_reasons=["AI classifier failed; flagging for human review as a precaution."],
                redact_spans=[],
                recommended_action="human_review",
                was_classified=False,
            )

    def apply_redactions(self, text: str, spans: List[str]) -> str:
        """Replace each redact_span with [EGRESS REDACTED]."""
        redacted = text
        for span in spans:
            if span and span in redacted:
                redacted = redacted.replace(span, "[EGRESS REDACTED]")
        return redacted
