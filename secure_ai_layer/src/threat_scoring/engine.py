from __future__ import annotations

import base64
import math
import re
import unicodedata
from copy import deepcopy
from typing import Any, Dict, List

from src.config.config_loader import get_policy_config


DEFAULT_SUSPICIOUS_KEYWORDS = {
    "ignore all previous instructions": {"weight": 12, "family": "prompt_injection"},
    "system prompt": {"weight": 10, "family": "prompt_injection"},
    "developer message": {"weight": 10, "family": "prompt_injection"},
    "dump the users table": {"weight": 10, "family": "data_exfiltration"},
    "exfiltrate": {"weight": 8, "family": "data_exfiltration"},
    "override safety": {"weight": 8, "family": "prompt_injection"},
    "pretend you are dan": {"weight": 10, "family": "prompt_injection"},
    "jailbreak": {"weight": 8, "family": "prompt_injection"},
    "select * from": {"weight": 7, "family": "sql_abuse"},
    "drop table": {"weight": 10, "family": "sql_abuse"},
    "where 1=1": {"weight": 8, "family": "sql_abuse"},
    "base64": {"weight": 5, "family": "encoded_payload"},
    "admin mode": {"weight": 6, "family": "privilege_escalation"},
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
        family_boost = min(12, len(semantic["families"]) * 6) if semantic["families"] else 0
        threat_score = min(100, pattern_score + session_score + semantic["score"] + family_boost)

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
            "detected_families": semantic["families"],
            "score_breakdown": {
                "pattern_match": pattern_score,
                "session_replay": session_score,
                "semantic_anomaly": semantic["score"],
                "adaptive_family_boost": family_boost,
            },
            "combined_signals": combined_signals,
            "semantic_signals": semantic["signals"],
            "explainability": {
                "method": semantic["method"],
                "normalized_input_length": len(unicodedata.normalize("NFKC", text)),
                "prior_risky_requests": session_context.get("risky_request_count", 0),
                "adaptive_families": semantic["families"],
            },
        }

    def _session_score(self, risky_request_count: int) -> int:
        if risky_request_count <= 0:
            return 0
        # 10 requests in the analysis window saturates the session replay dimension.
        return min(35, int(math.ceil(min(risky_request_count, 10) * 3.5)))

    def _semantic_score(self, text: str) -> Dict[str, Any]:
        config = get_policy_config()
        normalized = unicodedata.normalize("NFKC", text)
        lowered = normalized.lower()
        score = 0
        signals: List[str] = []
        families = set()

        for keyword, metadata in self._load_semantic_keywords(config).items():
            if keyword in lowered:
                score += int(metadata["weight"])
                signals.append(f"semantic:{keyword}")
                family = metadata.get("family")
                if family:
                    families.add(str(family))

        if normalized != text:
            score += 4
            signals.append("semantic:unicode_normalization")
            families.add("encoded_payload")

        if len(normalized) > 1600:
            score += 6
            signals.append("semantic:context_overflow")
            families.add("context_overflow")

        if self._looks_like_base64_payload(normalized):
            score += 8
            signals.append("semantic:encoded_payload")
            families.add("encoded_payload")

        ml_matches = self._match_ml_signatures(lowered, config)
        for match in ml_matches:
            score += int(match["weight"])
            signals.append(f"ml:{match['family']}:{match['pattern']}")
            families.add(match["family"])

        return {
            "score": min(25, score),
            "signals": signals,
            "families": sorted(families),
            "method": "heuristic-fallback+adaptive-policy",
        }

    def _load_semantic_keywords(self, config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        merged = deepcopy(DEFAULT_SUSPICIOUS_KEYWORDS)
        adaptive_signals = config.get("adaptive_defense", {}).get("semantic_signals", [])
        for signal in adaptive_signals:
            pattern = str(signal.get("pattern", "")).strip().lower()
            if not pattern:
                continue
            merged[pattern] = {
                "weight": int(signal.get("weight", 5)),
                "family": signal.get("family", "adaptive"),
            }
        return merged

    def _match_ml_signatures(self, text: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        signatures = config.get("adaptive_defense", {}).get("ml_signatures", [])
        for signature in signatures:
            pattern = str(signature.get("pattern", "")).strip().lower()
            if not pattern:
                continue

            strategy = str(signature.get("match_strategy", "literal")).strip().lower()
            matched = False
            if strategy == "word_boundary":
                matched = bool(re.search(rf"\b{re.escape(pattern)}\b", text))
            elif strategy == "regex":
                try:
                    matched = bool(re.search(pattern, text))
                except re.error:
                    matched = pattern in text
            else:
                matched = pattern in text

            if not matched:
                continue

            matches.append(
                {
                    "pattern": pattern,
                    "weight": min(12, int(signature.get("weight", 5))),
                    "family": str(signature.get("family", "adaptive")),
                }
            )

        return matches

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
