"""
AI Policy Recommendations from live audit traffic.

Analyzes recent blocked/flagged telemetry records to propose new semantic signals,
ML signatures, adjusted thresholds, and session hardening tweaks.
All suggestions require human approval before being applied.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.adapters.factory import get_provider_adapter
from src.ai.client import complete_json
from src.ai.schemas import PolicyRecommendationResult


RECOMMENDER_SYSTEM_PROMPT = """
You are a security policy advisor for an AI firewall called SUDARSHAN.
Analyze the supplied telemetry digest from recent blocked and flagged requests.
Return strict JSON only with the following keys:

- recommendations: list of objects, each with:
    - rule_type          ("semantic_signal" | "ml_signature" | "threshold" | "session_policy")
    - description        (short plain-language change description)
    - proposed_value     (dict with the specific mutation, e.g. {"pattern": "…", "weight": 8})
    - confidence         (float 0..1)
    - evidence_count     (int – number of telemetry events supporting this recommendation)
    - impact             ("LOW" | "MEDIUM" | "HIGH")
    - safe_to_auto_apply (bool – ALWAYS false unless evidence_count > 20 and confidence > 0.92)
- false_positive_candidates: list of strings (request_ids that look benign but were blocked)
- summary: string (2-3 sentence executive summary)

Rules:
- Recommend only additions, never deletions of existing rules.
- safe_to_auto_apply must be false unless the evidence is overwhelming.
- Limit recommendations to at most 6.
- If not enough data, return an empty recommendations list and explain in summary.
""".strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_telemetry_digest(
    records: List[Dict[str, Any]],
    min_events: int = 5,
    time_window_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """Summarise audit records into a compact digest for the recommender prompt."""
    blocked = [r for r in records if r.get("action_taken") in {"BLOCK", "BAN"}]
    flagged = [r for r in records if r.get("action_taken") == "FLAG"]

    signal_counter: Counter[str] = Counter()
    family_counter: Counter[str] = Counter()
    intent_counter: Counter[str] = Counter()
    session_ids = set()

    for record in [*blocked, *flagged]:
        for sig in record.get("injection_signals", []):
            signal_counter[sig] += 1
        for fam in record.get("detected_families", []) or []:
            family_counter[fam] += 1
        intent = record.get("sql_intent_token", "UNKNOWN_INTENT")
        intent_counter[intent] += 1
        sid = record.get("session_id", "")
        if sid:
            session_ids.add(sid)

    threat_scores = [int(r.get("threat_score", 0)) for r in blocked]
    avg_threat = round(sum(threat_scores) / len(threat_scores), 1) if threat_scores else 0

    # Sample up to 8 blocked input previews (sanitized) to give the LLM concrete examples
    sample_previews = [
        r.get("sanitized_input_preview") or r.get("input_preview", "")
        for r in blocked[:8]
        if r.get("sanitized_input_preview") or r.get("input_preview")
    ]

    return {
        "blocked_count": len(blocked),
        "flagged_count": len(flagged),
        "unique_sessions_affected": len(session_ids),
        "avg_threat_score_blocked": avg_threat,
        "top_signals": [{"signal": s, "count": c} for s, c in signal_counter.most_common(8)],
        "top_families": [{"family": f, "count": c} for f, c in family_counter.most_common(5)],
        "top_intents": [{"intent": i, "count": c} for i, c in intent_counter.most_common(5)],
        "sample_blocked_inputs": sample_previews,
        "min_events_threshold": min_events,
        "time_window_note": f"Last {time_window_hours} hours" if time_window_hours else "All available records",
    }


class PolicyRecommender:
    """
    Analyses live telemetry and produces AI-assisted policy recommendations.
    Requires explicit human approval before any recommendation is applied.
    """

    async def recommend(
        self,
        records: List[Dict[str, Any]],
        *,
        min_events: int = 5,
        time_window_hours: Optional[int] = None,
        include_false_positive_review: bool = True,
        provider_override: Optional[str] = None,
        model: Optional[str] = None,
    ) -> PolicyRecommendationResult:
        digest = _build_telemetry_digest(records, min_events=min_events, time_window_hours=time_window_hours)

        if digest["blocked_count"] + digest["flagged_count"] < min_events:
            return PolicyRecommendationResult(
                recommendations=[],
                false_positive_candidates=[],
                summary=(
                    f"Insufficient data: only {digest['blocked_count'] + digest['flagged_count']} "
                    f"blocked/flagged events found (minimum {min_events} required). "
                    "Collect more traffic before generating recommendations."
                ),
                digest=digest,
                generated_at=_utc_now_iso(),
            )

        _, adapter = get_provider_adapter(provider_override)
        prompt = (
            f"Telemetry digest:\n{digest}\n\n"
            f"Include false-positive review: {include_false_positive_review}\n"
            "Return JSON only."
        )

        try:
            result = await complete_json(
                adapter,
                system_prompt=RECOMMENDER_SYSTEM_PROMPT,
                user_message=prompt,
                schema=PolicyRecommendationResult,
                model=model,
                temperature=0.1,
            )
        except Exception as exc:
            # Graceful degradation: return a structured fallback with the raw digest
            top_signal = (digest["top_signals"][0]["signal"] if digest["top_signals"] else "unknown-signal")
            top_family = (digest["top_families"][0]["family"] if digest["top_families"] else "prompt_injection")
            return PolicyRecommendationResult(
                recommendations=[
                    {
                        "rule_type": "semantic_signal",
                        "description": f"Add weight to detected high-frequency signal '{top_signal}'",
                        "proposed_value": {"pattern": top_signal, "weight": 8, "family": top_family},
                        "confidence": 0.6,
                        "evidence_count": digest["top_signals"][0]["count"] if digest["top_signals"] else 0,
                        "impact": "MEDIUM",
                        "safe_to_auto_apply": False,
                    }
                ],
                false_positive_candidates=[],
                summary=(
                    f"AI analysis failed ({exc}). Fallback recommendation generated from digest. "
                    f"Detected {digest['blocked_count']} blocked and {digest['flagged_count']} flagged events. "
                    "Manual review recommended."
                ),
                digest=digest,
                generated_at=_utc_now_iso(),
            )

        # Inject digest so callers always have the evidence alongside the recommendations
        result.digest = digest
        result.generated_at = _utc_now_iso()
        return result
