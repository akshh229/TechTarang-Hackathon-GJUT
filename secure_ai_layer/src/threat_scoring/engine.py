from __future__ import annotations

import base64
import math
import re
import unicodedata
from typing import Any, Dict, List

from src.config.config_loader import get_policy_config


SUSPICIOUS_KEYWORDS = {
    "ignore all previous instructions": 12,
    "system prompt": 10,
    "developer message": 10,
    "dump the users table": 10,
    "exfiltrate": 8,
    "override safety": 8,
    "pretend you are dan": 10,
    "jailbreak": 8,
    "select * from": 7,
    "drop table": 10,
    "where 1=1": 8,
    "base64": 5,
    "admin mode": 6,
}


class ThreatScoringEngine:
    """Computes a composite threat score using pattern, session, and semantic signals."""

    def assess_text(
        self,
        text: str,
        inspection: Dict[str, Any],
        session_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = get_policy_config()
        thresholds = config.get("risk_thresholds", {"amber": 30, "red": 60})

        pattern_score = min(40, int(inspection.get("pattern_score", 0)))
        semantic = self._semantic_score(text)
        session_score = self._session_score(session_context.get("risky_request_count", 0))
        threat_score = min(100, pattern_score + session_score + semantic["score"])

        risk_level = "GREEN"
        if threat_score >= int(thresholds.get("red", 60)):
            risk_level = "RED"
        elif threat_score >= int(thresholds.get("amber", 30)):
            risk_level = "AMBER"

        action_taken = "PASS"
        if risk_level == "AMBER":
            action_taken = "FLAG"
        elif risk_level == "RED":
            action_taken = "BLOCK"

        combined_signals = list(dict.fromkeys(inspection.get("triggered_patterns", []) + semantic["signals"]))

        return {
            "risk_level": risk_level,
            "action_taken": action_taken,
            "threat_score": threat_score,
            "score_breakdown": {
                "pattern_match": pattern_score,
                "session_replay": session_score,
                "semantic_anomaly": semantic["score"],
            },
            "combined_signals": combined_signals,
            "semantic_signals": semantic["signals"],
            "explainability": {
                "method": semantic["method"],
                "normalized_input_length": len(unicodedata.normalize("NFKC", text)),
                "prior_risky_requests": session_context.get("risky_request_count", 0),
            },
        }

    def _session_score(self, risky_request_count: int) -> int:
        if risky_request_count <= 0:
            return 0
        # 10 requests in the analysis window saturates the session replay dimension.
        return min(35, int(math.ceil(min(risky_request_count, 10) * 3.5)))

    def _semantic_score(self, text: str) -> Dict[str, Any]:
        normalized = unicodedata.normalize("NFKC", text)
        lowered = normalized.lower()
        score = 0
        signals: List[str] = []

        for keyword, weight in SUSPICIOUS_KEYWORDS.items():
            if keyword in lowered:
                score += weight
                signals.append(f"semantic:{keyword}")

        if normalized != text:
            score += 4
            signals.append("semantic:unicode_normalization")

        if len(normalized) > 1600:
            score += 6
            signals.append("semantic:context_overflow")

        if self._looks_like_base64_payload(normalized):
            score += 8
            signals.append("semantic:encoded_payload")

        return {
            "score": min(25, score),
            "signals": signals,
            "method": "heuristic-fallback",
        }

    def _looks_like_base64_payload(self, text: str) -> bool:
        for token in re.findall(r"[A-Za-z0-9+/=]{24,}", text):
            if len(token) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore").lower()
            except Exception:
                continue

            if any(keyword in decoded for keyword in ("ignore", "system prompt", "override", "dump")):
                return True

        return False
