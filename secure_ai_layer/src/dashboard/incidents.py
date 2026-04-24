from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _normalize_signal(signal: str) -> str:
    if not signal:
        return "unknown-signal"
    lowered = signal.lower().strip()
    if lowered.startswith("ml:"):
        parts = lowered.split(":", 2)
        if len(parts) >= 3:
            return parts[2]
    if lowered.startswith("semantic:"):
        return lowered.split(":", 1)[1]
    return lowered


def infer_incident_family(record: Dict[str, Any]) -> str:
    signals = record.get("injection_signals") or []
    for signal in signals:
        lowered = str(signal).lower()
        if lowered.startswith("ml:"):
            parts = lowered.split(":", 2)
            if len(parts) >= 2 and parts[1]:
                return parts[1]
        if "encoded_payload" in lowered or "base64" in lowered:
            return "encoded_payload"
        if "system prompt" in lowered or "ignore all previous instructions" in lowered:
            return "prompt_injection"
        if "run this command" in lowered or "curl | sh" in lowered:
            return "tool_execution"
        if "memory" in lowered:
            return "memory_poisoning"

    explanation = (record.get("block_explanation") or "").lower()
    if "override instructions" in explanation:
        return "prompt_injection"
    if "protected data" in explanation:
        return "data_access"
    return "unknown"


def _cluster_key(record: Dict[str, Any]) -> str:
    family = infer_incident_family(record)
    signals = record.get("injection_signals") or []
    top_signal = _normalize_signal(signals[0]) if signals else "no-signal"
    intent = record.get("sql_intent_token", "UNKNOWN_INTENT")
    action = record.get("action_taken", "PASS")
    return "|".join([family, top_signal, intent, action])


def _incident_label(family: str, top_signal: str) -> str:
    pretty_family = family.replace("_", " ").title()
    pretty_signal = top_signal.replace("_", " ")
    if top_signal == "no-signal":
        return pretty_family
    return f"{pretty_family}: {pretty_signal}"


def _build_incident_payload(cluster_key: str, cluster_records: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    cluster_records.sort(key=lambda record: record.get("timestamp", ""), reverse=True)
    family = infer_incident_family(cluster_records[0])
    signal_counter = Counter()
    session_ids = set()
    action_counter = Counter()
    score_total = 0

    for record in cluster_records:
        signal_counter.update(_normalize_signal(signal) for signal in (record.get("injection_signals") or []))
        session_ids.add(record.get("session_id", "unknown-session"))
        action_counter[record.get("action_taken", "PASS")] += 1
        score_total += int(record.get("threat_score", 0))

    top_signal = signal_counter.most_common(1)[0][0] if signal_counter else "no-signal"
    first_seen = min(cluster_records, key=lambda record: record.get("timestamp", ""))["timestamp"]
    last_seen = max(cluster_records, key=lambda record: record.get("timestamp", ""))["timestamp"]
    avg_score = round(score_total / len(cluster_records), 1) if cluster_records else 0
    severity_score = min(
        100,
        int(avg_score * 0.7) + (len(cluster_records) * 4) + (len(session_ids) * 3),
    )
    incident_id = hashlib.sha1(cluster_key.encode("utf-8")).hexdigest()[:12]

    return (
        {
            "incident_id": incident_id,
            "label": _incident_label(family, top_signal),
            "family": family,
            "top_signal": top_signal,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_count": len(cluster_records),
            "affected_sessions": len(session_ids),
            "actions": dict(action_counter),
            "top_signals": [
                {"signal": signal, "count": count}
                for signal, count in signal_counter.most_common(4)
            ],
            "avg_threat_score": avg_score,
            "severity_score": severity_score,
            "sample_input": cluster_records[0].get("input_preview", ""),
            "latest_explanation": cluster_records[0].get("block_explanation", ""),
            "latest_safe_rewrite": cluster_records[0].get("safe_rewrite", ""),
            "related_request_ids": [
                record.get("request_id")
                for record in cluster_records[:10]
                if record.get("request_id")
            ],
        },
        cluster_records,
    )


def _build_incident_lookup(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    relevant_records = [
        record
        for record in records
        if record.get("action_taken") in {"FLAG", "BLOCK", "BAN"}
    ]
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in relevant_records:
        grouped[_cluster_key(record)].append(record)

    incident_lookup: Dict[str, Dict[str, Any]] = {}
    for cluster_key, cluster_records in grouped.items():
        incident, sorted_records = _build_incident_payload(cluster_key, cluster_records)
        incident_lookup[incident["incident_id"]] = {
            "incident": incident,
            "records": sorted_records,
        }

    return incident_lookup


def build_incidents(records: List[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    incidents = [item["incident"] for item in _build_incident_lookup(records).values()]

    incidents.sort(
        key=lambda incident: (
            incident["severity_score"],
            _parse_timestamp(incident["last_seen"]).timestamp(),
        ),
        reverse=True,
    )
    return incidents[:limit]


def get_incident_records(
    records: List[Dict[str, Any]],
    incident_id: str,
    *,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    incident_lookup = _build_incident_lookup(records)
    incident_payload = incident_lookup.get(incident_id)
    if not incident_payload:
        return []
    return incident_payload["records"][:limit]
