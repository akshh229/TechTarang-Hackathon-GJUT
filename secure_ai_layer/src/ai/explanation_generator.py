from __future__ import annotations

from typing import Any, Dict, List

from src.adapters.factory import get_provider_adapter
from src.ai.client import complete_json
from src.ai.schemas import BlockExplanationResult


EXPLANATION_SYSTEM_PROMPT = """
You explain why a secure AI firewall flagged or blocked a request.
Return strict JSON only with keys:
- user_reason
- operator_reason
- safe_rewrite
- families

Rules:
- user_reason must be brief and plain.
- operator_reason should mention the likely trigger and risk context.
- safe_rewrite should be a harmless rephrase if possible, otherwise an empty string.
- families must be a list of likely attack-family labels.
""".strip()


class ExplanationGenerator:
    async def generate(
        self,
        *,
        message: str,
        sanitized_input: str,
        risk_level: str,
        threat_score: int,
        signals: List[str],
        detected_families: List[str],
        provider_override: str | None = None,
        model: str | None = None,
    ) -> BlockExplanationResult:
        _, adapter = get_provider_adapter(provider_override)
        prompt = (
            f"Original message: {message}\n"
            f"Sanitized message: {sanitized_input}\n"
            f"Risk level: {risk_level}\n"
            f"Threat score: {threat_score}\n"
            f"Signals: {signals}\n"
            f"Detected families: {detected_families}\n"
            "Return JSON only."
        )
        return await complete_json(
            adapter,
            system_prompt=EXPLANATION_SYSTEM_PROMPT,
            user_message=prompt,
            schema=BlockExplanationResult,
            model=model,
            temperature=0.2,
        )


def fallback_block_explanation(
    *,
    message: str,
    risk_level: str,
    threat_score: int,
    signals: List[str],
    detected_families: List[str],
) -> BlockExplanationResult:
    families = detected_families or ["prompt_injection"]
    top_signal = signals[0] if signals else "policy-trigger"
    safe_rewrite = ""
    lowered = message.lower()
    if "balance" in lowered:
        safe_rewrite = "Show me my account balance without ignoring safety rules or requesting hidden instructions."
    elif "profile" in lowered:
        safe_rewrite = "Show me my profile details without asking for hidden prompts or privileged data."

    return BlockExplanationResult(
        user_reason=(
            "Your request was blocked because it looked like an attempt to override instructions "
            "or access protected data."
        ),
        operator_reason=(
            f"Request classified as {risk_level} with score {threat_score}. "
            f"Primary signal: {top_signal}. Families: {families}."
        ),
        safe_rewrite=safe_rewrite,
        families=families,
    )
