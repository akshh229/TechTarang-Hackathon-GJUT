from __future__ import annotations

import math
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover - optional dependency in some environments
    SentenceTransformer = None


FAMILY_RESEARCH_NOTES: Dict[str, str] = {
    "indirect_prompt_injection": (
        "Zero-click prompt injection hidden in email, documents, or retrieved content "
        "that causes assistants to exfiltrate data without explicit user approval."
    ),
    "tool_execution": (
        "Repository, IDE, or shell-instruction attacks where malicious content tricks an "
        "AI assistant into executing terminal commands or scripts."
    ),
    "memory_poisoning": (
        "Persistent manipulation that stores attacker instructions in memory, profile, "
        "or session state so the behavior survives later requests."
    ),
    "moderation_evasion": (
        "Hidden instructions designed to bypass trust, moderation, ad review, or policy "
        "approval systems for fraud or abuse."
    ),
    "encoded_payload": (
        "Obfuscated prompt injection using base64, unicode smuggling, HTML comments, or "
        "other transformed payloads to hide malicious instructions."
    ),
}

TRAIT_KEYWORDS: Dict[str, List[str]] = {
    "zero_click": ["zero-click", "no user interaction", "silent", "background"],
    "data_exfiltration": ["exfiltrate", "leak", "transmit", "send to attacker", "steal data"],
    "remote_execution": ["remote code execution", "rce", "shell command", "execute command", "curl | sh"],
    "supply_chain": ["readme", "repository", "github", "dependency", "supply chain"],
    "persistence": ["memory", "persistent", "remember", "profile", "long-term"],
    "obfuscation": ["base64", "encoded", "unicode", "hidden prompt", "html comment", "invisible text"],
}

RISKY_PHRASE_PATTERNS = [
    r"curl\s*\|\s*sh",
    r"powershell\s+-encodedcommand",
    r"run this command",
    r"ignore [a-z ]{0,30}instructions",
    r"exfiltrate [a-z ]{0,40}files",
    r"save (?:this )?to memory",
    r"remember this forever",
    r"remote code execution",
    r"prompt injection",
    r"hidden prompt",
]


def _normalize(text: str) -> str:
    return " ".join((text or "").lower().split())


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_:/|.-]{3,}", _normalize(text)))


def _cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    left_values = list(left)
    right_values = list(right)
    numerator = sum(a * b for a, b in zip(left_values, right_values))
    left_norm = math.sqrt(sum(a * a for a in left_values))
    right_norm = math.sqrt(sum(b * b for b in right_values))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)


@lru_cache(maxsize=1)
def _get_embedding_model() -> SentenceTransformer | None:
    if SentenceTransformer is None:
        return None
    try:
        return SentenceTransformer("all-MiniLM-L6-v2", local_files_only=True)
    except Exception:
        return None


class AdaptiveThreatIntelligence:
    """ML-style report analyzer with embedding support and lexical fallback."""

    def __init__(self, family_profiles: Dict[str, Dict[str, Any]]):
        self.family_profiles = family_profiles

    def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        text = self._compose_report_text(report)
        family_scores, backend = self._score_families(text)
        traits = self._detect_traits(text)
        signatures = self._extract_signatures(report, text, family_scores)
        actions = self._recommend_actions(family_scores, traits, report)

        selected = [
            item["family"]
            for item in family_scores
            if item["confidence"] >= 0.35 or item["matched_aliases"]
        ][:3]
        if not selected and family_scores:
            selected = [family_scores[0]["family"]]

        return {
            "model_backend": backend,
            "family_rankings": family_scores,
            "selected_families": selected,
            "traits": traits,
            "generated_signatures": signatures,
            "recommended_actions": actions,
        }

    def _compose_report_text(self, report: Dict[str, Any]) -> str:
        values = [
            report.get("title", ""),
            report.get("summary", ""),
            report.get("report_text", ""),
            " ".join(report.get("attack_surface", [])),
            " ".join(report.get("indicators", [])),
            " ".join(report.get("payload_examples", [])),
        ]
        return _normalize(" ".join(part for part in values if part))

    def _score_families(self, report_text: str) -> Tuple[List[Dict[str, Any]], str]:
        prototype_texts = {
            family: self._family_prototype_text(family, profile)
            for family, profile in self.family_profiles.items()
        }
        model = _get_embedding_model()
        backend = "sentence-transformers" if model else "lexical-fallback"
        embedding_scores: Dict[str, float] = {}

        if model:
            texts = [report_text, *prototype_texts.values()]
            try:
                embeddings = model.encode(texts, normalize_embeddings=True)
                report_embedding = embeddings[0]
                for family, embedding in zip(prototype_texts.keys(), embeddings[1:]):
                    embedding_scores[family] = max(0.0, float(_cosine_similarity(report_embedding, embedding)))
            except Exception:
                backend = "lexical-fallback"
                embedding_scores = {}

        report_tokens = _tokenize(report_text)
        rankings: List[Dict[str, Any]] = []
        for family, profile in self.family_profiles.items():
            aliases = [_normalize(alias) for alias in profile.get("aliases", [])]
            matched_aliases = [alias for alias in aliases if alias and alias in report_text]
            lexical_score = self._lexical_similarity(report_tokens, _tokenize(prototype_texts[family]))
            embedding_score = embedding_scores.get(family, 0.0)
            confidence = max(lexical_score, embedding_score)
            if matched_aliases:
                confidence = max(confidence, min(0.98, 0.55 + (0.12 * len(matched_aliases))))

            rankings.append(
                {
                    "family": family,
                    "confidence": round(confidence, 3),
                    "matched_aliases": matched_aliases[:6],
                    "lexical_score": round(lexical_score, 3),
                    "embedding_score": round(embedding_score, 3),
                }
            )

        rankings.sort(key=lambda item: item["confidence"], reverse=True)
        return rankings, backend

    def _family_prototype_text(self, family: str, profile: Dict[str, Any]) -> str:
        text_parts = [
            family.replace("_", " "),
            FAMILY_RESEARCH_NOTES.get(family, ""),
            " ".join(profile.get("aliases", [])),
            " ".join(profile.get("surfaces", [])),
            " ".join(rule.get("pattern", "") for rule in profile.get("injection_rules", [])),
            " ".join(signal.get("pattern", "") for signal in profile.get("semantic_signals", [])),
            " ".join(profile.get("prompt_guardrails", [])),
        ]
        return _normalize(" ".join(part for part in text_parts if part))

    def _lexical_similarity(self, left_tokens: set[str], right_tokens: set[str]) -> float:
        if not left_tokens or not right_tokens:
            return 0.0
        overlap = len(left_tokens.intersection(right_tokens))
        union = len(left_tokens.union(right_tokens))
        if union == 0:
            return 0.0
        return overlap / union

    def _detect_traits(self, report_text: str) -> List[str]:
        traits: List[str] = []
        for trait, keywords in TRAIT_KEYWORDS.items():
            if any(keyword in report_text for keyword in keywords):
                traits.append(trait)
        return traits

    def _extract_signatures(
        self,
        report: Dict[str, Any],
        report_text: str,
        family_scores: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        primary_family = family_scores[0]["family"] if family_scores else "indirect_prompt_injection"
        seen = set()
        signatures: List[Dict[str, Any]] = []

        raw_candidates: List[str] = []
        raw_candidates.extend(report.get("indicators", []))
        raw_candidates.extend(report.get("payload_examples", []))
        raw_candidates.extend(match.group(0) for pattern in RISKY_PHRASE_PATTERNS for match in re.finditer(pattern, report_text))

        for candidate in raw_candidates:
            compact = " ".join(str(candidate).split()).strip()
            lowered = compact.lower()
            if not compact or lowered in seen:
                continue
            if len(compact) > 120 or len(compact.split()) > 16:
                continue

            seen.add(lowered)
            confidence = 0.72
            weight = 7
            strategy = "literal"
            if re.search(r"[^a-z0-9 ]", lowered):
                strategy = "word_boundary"
            if any(token in lowered for token in ("curl | sh", "encodedcommand", "exfiltrate", "remote code execution")):
                confidence = 0.92
                weight = 10
            elif any(token in lowered for token in ("memory", "remember", "hidden prompt", "prompt injection")):
                confidence = 0.84
                weight = 8

            signatures.append(
                {
                    "pattern": lowered,
                    "family": primary_family,
                    "weight": weight,
                    "confidence": round(confidence, 2),
                    "match_strategy": strategy,
                    "source": "attack_report_ml",
                }
            )

        return signatures[:12]

    def _recommend_actions(
        self,
        family_scores: List[Dict[str, Any]],
        traits: List[str],
        report: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        severity = str(report.get("severity", "HIGH")).upper()
        top_families = [item["family"] for item in family_scores[:2]]
        actions: List[Dict[str, Any]] = []

        for family in top_families:
            actions.append(
                {
                    "family": family,
                    "action": "block_and_log",
                    "reason": f"Auto-block repeat patterns linked to {family.replace('_', ' ')}.",
                }
            )

        if "remote_execution" in traits or "supply_chain" in traits:
            actions.append(
                {
                    "family": top_families[0] if top_families else "tool_execution",
                    "action": "tighten_rate_limit",
                    "reason": "Reduce command-driven attack loops and slow repeated exploitation attempts.",
                }
            )
        if "data_exfiltration" in traits or severity == "CRITICAL":
            actions.append(
                {
                    "family": top_families[0] if top_families else "indirect_prompt_injection",
                    "action": "shrink_payload_window",
                    "reason": "Lower payload size to reduce room for hidden exfiltration prompts.",
                }
            )
        if "persistence" in traits:
            actions.append(
                {
                    "family": "memory_poisoning",
                    "action": "harden_session_cooldown",
                    "reason": "Shorten the path to suspicious-session escalation for persistent manipulation.",
                }
            )

        deduped: Dict[str, Dict[str, Any]] = {}
        for action in actions:
            deduped[f"{action['family']}:{action['action']}"] = action
        return list(deduped.values())
