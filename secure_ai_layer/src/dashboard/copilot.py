from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Sequence

from pydantic import BaseModel, Field

from src.adapters.factory import get_provider_adapter
from src.ai.client import complete_json
from src.dashboard.incidents import build_incidents, get_incident_records, infer_incident_family


DASHBOARD_COPILOT_SYSTEM_PROMPT = """
You are a security operations dashboard copilot.
Answer only from the provided incidents and records.
Do not invent telemetry, time windows, or policy changes.
Return strict JSON only with keys:
- answer
- supporting_metrics
- cited_records
- cited_incidents
- suggested_next_actions
- grounding

Rules:
- answer must be short, specific, and grounded in the supplied telemetry.
- supporting_metrics should contain 2 to 4 concise metrics with string values.
- cited_records must only reference request_ids present in the supplied context.
- cited_incidents must only reference incident_ids present in the supplied context.
- suggested_next_actions should be concrete operator actions.
- grounding must include scope_label, record_count, and incident_count.
""".strip()


class CopilotMetric(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=120)


class CopilotRecordCitation(BaseModel):
    request_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    risk_level: str = Field(min_length=1)
    action_taken: str = Field(min_length=1)
    signal: str = Field(default="", max_length=120)


class CopilotIncidentCitation(BaseModel):
    incident_id: str = Field(min_length=1)
    label: str = Field(min_length=1, max_length=160)
    family: str = Field(min_length=1, max_length=80)
    severity_score: int = Field(ge=0, le=100)
    event_count: int = Field(ge=0)


class CopilotGrounding(BaseModel):
    scope_label: str = Field(min_length=1, max_length=120)
    record_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)


class DashboardCopilotResponse(BaseModel):
    answer: str = Field(min_length=1)
    supporting_metrics: List[CopilotMetric] = Field(default_factory=list)
    cited_records: List[CopilotRecordCitation] = Field(default_factory=list)
    cited_incidents: List[CopilotIncidentCitation] = Field(default_factory=list)
    suggested_next_actions: List[str] = Field(default_factory=list)
    grounding: CopilotGrounding


def _clip(value: str, limit: int = 180) -> str:
    if not value:
        return ""
    clean_value = " ".join(str(value).split())
    return clean_value if len(clean_value) <= limit else f"{clean_value[: limit - 1]}…"


def _scope_label(*, family: str | None = None, incident: Dict[str, Any] | None = None) -> str:
    if incident:
        return f"Incident {incident.get('label', incident.get('incident_id', 'selected-scope'))}"
    if family:
        return f"Family {family.replace('_', ' ')}"
    return "Recent incidents and records"


def _record_citation(record: Dict[str, Any]) -> CopilotRecordCitation:
    return CopilotRecordCitation(
        request_id=str(record.get("request_id", "unknown-request")),
        timestamp=str(record.get("timestamp", "")),
        risk_level=str(record.get("risk_level", "GREEN")),
        action_taken=str(record.get("action_taken", "PASS")),
        signal=_clip((record.get("injection_signals") or ["no-signal"])[0], limit=72),
    )


def _incident_citation(incident: Dict[str, Any]) -> CopilotIncidentCitation:
    return CopilotIncidentCitation(
        incident_id=str(incident.get("incident_id", "unknown-incident")),
        label=_clip(incident.get("label", "Unnamed incident"), limit=140),
        family=str(incident.get("family", "unknown")),
        severity_score=int(incident.get("severity_score", 0)),
        event_count=int(incident.get("event_count", 0)),
    )


def _metric(label: str, value: Any) -> CopilotMetric:
    return CopilotMetric(label=label, value=str(value))


def _select_scope(
    records: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    *,
    family: str | None = None,
    incident_id: str | None = None,
    record_limit: int = 40,
    incident_limit: int = 6,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any] | None]:
    selected_incident = None
    if incident_id:
        selected_incident = next(
            (incident for incident in incidents if incident.get("incident_id") == incident_id),
            None,
        )
        scoped_records = get_incident_records(records, incident_id, limit=record_limit)
        scoped_incidents = [selected_incident] if selected_incident else []
    elif family:
        scoped_records = [
            record
            for record in records
            if infer_incident_family(record) == family
        ][:record_limit]
        scoped_incidents = [
            incident
            for incident in incidents
            if incident.get("family") == family
        ][:incident_limit]
    else:
        scoped_records = records[:record_limit]
        scoped_incidents = incidents[:incident_limit]

    if not scoped_records and records:
        scoped_records = records[:record_limit]
    if not scoped_incidents and incidents and not incident_id:
        scoped_incidents = incidents[:incident_limit]

    return scoped_records, scoped_incidents, selected_incident


def _fallback_answer(
    question: str,
    records: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    *,
    family: str | None = None,
    selected_incident: Dict[str, Any] | None = None,
) -> DashboardCopilotResponse:
    action_counts = Counter(record.get("action_taken", "PASS") for record in records)
    signal_counts = Counter()
    suspicious_sessions = set()

    for record in records:
        signal_counts.update(record.get("injection_signals") or [])
        session_state = record.get("session_state") or {}
        if session_state.get("suspicious") or session_state.get("cooldown_active"):
            suspicious_sessions.add(record.get("session_id", "unknown-session"))

    blocked_count = action_counts.get("BLOCK", 0) + action_counts.get("BAN", 0)
    flagged_count = action_counts.get("FLAG", 0)
    top_signal = signal_counts.most_common(1)[0][0] if signal_counts else "no dominant signal"
    top_incident = incidents[0] if incidents else selected_incident
    question_lower = question.lower()
    scope_label = _scope_label(family=family, incident=selected_incident)

    if not records:
        answer = "No matching telemetry is available in the current dashboard window."
    elif "spike" in question_lower or "why" in question_lower:
        incident_label = top_incident.get("label", "the leading cluster") if top_incident else "the leading cluster"
        answer = (
            f"{scope_label} is being driven by {blocked_count} blocked and {flagged_count} flagged "
            f"events, led by {incident_label} and the signal {top_signal}."
        )
    elif "session" in question_lower:
        answer = (
            f"{scope_label} includes {len(suspicious_sessions)} suspicious sessions. "
            f"The highest-pressure activity is tied to {top_signal}."
        )
    elif "tool" in question_lower:
        tool_incidents = [incident for incident in incidents if incident.get("family") == "tool_execution"]
        if tool_incidents:
            answer = (
                f"Tool-execution activity is present in {len(tool_incidents)} active clusters, "
                f"with {tool_incidents[0]['label']} currently the most severe."
            )
        else:
            answer = f"{scope_label} does not currently show a dominant tool-execution cluster."
    else:
        headline = top_incident.get("label", "the latest risky cluster") if top_incident else "the latest risky cluster"
        answer = (
            f"{scope_label} currently shows {len(records)} recent records with {blocked_count} blocked "
            f"events. {headline} is the strongest cluster in scope."
        )

    suggested_actions = [
        f"Review the cited records for {top_signal} and confirm whether the current guardrails are sufficient.",
        "Inspect repeated sessions for escalation or cooldown patterns before the cluster grows.",
    ]
    if top_incident:
        suggested_actions.append(
            f"Prioritize triage for {top_incident.get('label', 'the top incident')} because it has the highest severity in scope."
        )

    return DashboardCopilotResponse(
        answer=answer,
        supporting_metrics=[
            _metric("Scope", scope_label),
            _metric("Blocked", blocked_count),
            _metric("Flagged", flagged_count),
            _metric("Suspicious sessions", len(suspicious_sessions)),
        ],
        cited_records=[_record_citation(record) for record in records[:3]],
        cited_incidents=[_incident_citation(incident) for incident in incidents[:2]],
        suggested_next_actions=suggested_actions[:3],
        grounding=CopilotGrounding(
            scope_label=scope_label,
            record_count=len(records),
            incident_count=len(incidents),
        ),
    )


def _sanitize_response(
    response: DashboardCopilotResponse,
    *,
    records: Sequence[Dict[str, Any]],
    incidents: Sequence[Dict[str, Any]],
    family: str | None = None,
    selected_incident: Dict[str, Any] | None = None,
) -> DashboardCopilotResponse:
    allowed_record_ids = {str(record.get("request_id")) for record in records if record.get("request_id")}
    allowed_incident_ids = {str(incident.get("incident_id")) for incident in incidents if incident.get("incident_id")}

    cited_records = [
        citation
        for citation in response.cited_records
        if citation.request_id in allowed_record_ids
    ]
    cited_incidents = [
        citation
        for citation in response.cited_incidents
        if citation.incident_id in allowed_incident_ids
    ]

    supporting_metrics = response.supporting_metrics[:4]
    if not supporting_metrics:
        supporting_metrics = _fallback_answer(
            "",
            list(records),
            list(incidents),
            family=family,
            selected_incident=selected_incident,
        ).supporting_metrics

    suggested_next_actions = [action for action in response.suggested_next_actions if action][:3]
    if not suggested_next_actions:
        suggested_next_actions = _fallback_answer(
            "",
            list(records),
            list(incidents),
            family=family,
            selected_incident=selected_incident,
        ).suggested_next_actions

    return DashboardCopilotResponse(
        answer=response.answer,
        supporting_metrics=supporting_metrics,
        cited_records=cited_records or [_record_citation(record) for record in list(records)[:3]],
        cited_incidents=cited_incidents or [_incident_citation(incident) for incident in list(incidents)[:2]],
        suggested_next_actions=suggested_next_actions,
        grounding=CopilotGrounding(
            scope_label=response.grounding.scope_label
            if response.grounding.scope_label
            else _scope_label(family=family, incident=selected_incident),
            record_count=len(records),
            incident_count=len(incidents),
        ),
    )


class DashboardCopilot:
    async def answer_query(
        self,
        *,
        question: str,
        records: List[Dict[str, Any]],
        family: str | None = None,
        incident_id: str | None = None,
        provider_override: str | None = None,
        model: str | None = None,
    ) -> DashboardCopilotResponse:
        incidents = build_incidents(records, limit=12)
        scoped_records, scoped_incidents, selected_incident = _select_scope(
            records,
            incidents,
            family=family,
            incident_id=incident_id,
        )

        if not scoped_records and not scoped_incidents:
            return _fallback_answer(
                question,
                scoped_records,
                scoped_incidents,
                family=family,
                selected_incident=selected_incident,
            )

        scope_label = _scope_label(family=family, incident=selected_incident)
        context_incidents = [
            {
                "incident_id": incident.get("incident_id"),
                "label": incident.get("label"),
                "family": incident.get("family"),
                "severity_score": incident.get("severity_score"),
                "event_count": incident.get("event_count"),
                "top_signal": incident.get("top_signal"),
            }
            for incident in scoped_incidents
        ]
        context_records = [
            {
                "request_id": record.get("request_id"),
                "timestamp": record.get("timestamp"),
                "risk_level": record.get("risk_level"),
                "action_taken": record.get("action_taken"),
                "incident_family": infer_incident_family(record),
                "signals": record.get("injection_signals", []),
                "block_explanation": _clip(record.get("block_explanation", ""), 120),
                "input_preview": _clip(record.get("input_preview", ""), 120),
            }
            for record in scoped_records[:8]
        ]
        context_prompt = (
            f"Question: {question}\n"
            f"Scope: {scope_label}\n"
            f"Incidents: {context_incidents}\n"
            f"Records: {context_records}\n"
            "Return JSON only."
        )

        try:
            _, adapter = get_provider_adapter(provider_override)
            response = await complete_json(
                adapter,
                system_prompt=DASHBOARD_COPILOT_SYSTEM_PROMPT,
                user_message=context_prompt,
                schema=DashboardCopilotResponse,
                model=model,
                temperature=0.2,
            )
            return _sanitize_response(
                response,
                records=scoped_records,
                incidents=scoped_incidents,
                family=family,
                selected_incident=selected_incident,
            )
        except Exception:
            return _fallback_answer(
                question,
                scoped_records,
                scoped_incidents,
                family=family,
                selected_incident=selected_incident,
            )
