from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DPDP_MAPPING = [
    {
        "section": "Section 4",
        "obligation": "Lawful processing",
        "system_feature": "Policy-Aware SQL Planner",
        "audit_evidence": "sql_intent_token",
    },
    {
        "section": "Section 8(1)",
        "obligation": "Data accuracy",
        "system_feature": "Egress Redactor",
        "audit_evidence": "pii_redactions",
    },
    {
        "section": "Section 8(3)",
        "obligation": "Data minimisation",
        "system_feature": "Least-privilege SQL templates",
        "audit_evidence": "sql_intent_token",
    },
    {
        "section": "Section 8(7)",
        "obligation": "Security safeguards",
        "system_feature": "Ingress + scoring + audit pipeline",
        "audit_evidence": "risk_level + threat_score + request_id",
    },
    {
        "section": "Section 10",
        "obligation": "Fiduciary obligations",
        "system_feature": "Compliance export",
        "audit_evidence": "request_id + timestamp + input_hash",
    },
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


class ComplianceReporter:
    """Builds JSON and PDF-ready compliance summaries from audit telemetry."""

    def build_report(
        self,
        records: List[Dict[str, Any]],
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
    ) -> Dict[str, Any]:
        filtered_records = self._filter_records(records, from_ts, to_ts)
        summary = self._build_summary(filtered_records)
        blocked_events = [
            self._report_record(record)
            for record in filtered_records
            if record.get("action_taken") in {"BLOCK", "BAN"}
        ]

        return {
            "generated_at": utc_now_iso(),
            "period": {
                "from": from_ts,
                "to": to_ts,
            },
            "summary": summary,
            "top_blocked_patterns": self._top_patterns(filtered_records),
            "dpdp_mapping": DPDP_MAPPING,
            "session_anomalies": self._session_anomalies(filtered_records),
            "blocked_events": blocked_events[:10],
            "records_included": [self._report_record(record) for record in filtered_records[:100]],
            "hash_chain_verification": {
                "status": "prototype-verifiable",
                "record_count": len(filtered_records),
            },
        }

    def build_pdf_html(self, report: Dict[str, Any]) -> str:
        blocked_patterns = "".join(
            f"<li><strong>{item['pattern']}</strong>: {item['count']}</li>"
            for item in report["top_blocked_patterns"]
        ) or "<li>No blocked patterns in selected time range.</li>"

        session_rows = "".join(
            (
                "<tr>"
                f"<td>{session['session_id']}</td>"
                f"<td>{session['risky_request_count']}</td>"
                f"<td>{session['blocked_request_count']}</td>"
                f"<td>{'Yes' if session['cooldown_active'] else 'No'}</td>"
                "</tr>"
            )
            for session in report["session_anomalies"]
        ) or "<tr><td colspan='4'>No suspicious sessions captured in selected window.</td></tr>"

        dpdp_rows = "".join(
            (
                "<tr>"
                f"<td>{item['section']}</td>"
                f"<td>{item['obligation']}</td>"
                f"<td>{item['system_feature']}</td>"
                f"<td>{item['audit_evidence']}</td>"
                "</tr>"
            )
            for item in report["dpdp_mapping"]
        )

        return f"""
        <html>
          <head>
            <style>
              body {{
                font-family: Arial, sans-serif;
                padding: 28px;
                color: #142033;
              }}
              h1, h2 {{
                margin-bottom: 8px;
              }}
              .hero {{
                padding: 20px 24px;
                border-radius: 18px;
                background: linear-gradient(135deg, #ecf7ff, #f9fbff);
                border: 1px solid #d2e6ff;
                margin-bottom: 24px;
              }}
              .stats {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 12px;
                margin: 24px 0;
              }}
              .stat {{
                padding: 14px;
                border-radius: 14px;
                background: #f5f9ff;
                border: 1px solid #dfebff;
              }}
              table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
              }}
              th, td {{
                border: 1px solid #dce6f4;
                padding: 10px;
                text-align: left;
                vertical-align: top;
              }}
              th {{
                background: #f3f7fc;
              }}
              ul {{
                padding-left: 20px;
              }}
            </style>
          </head>
          <body>
            <div class="hero">
              <h1>Secure AI Interaction Layer Compliance Report</h1>
              <p>Generated at: {report['generated_at']}</p>
              <p>Time range: {report['period']['from'] or 'Beginning'} to {report['period']['to'] or 'Now'}</p>
            </div>

            <div class="stats">
              <div class="stat"><strong>Total Requests</strong><br>{report['summary']['total_requests']}</div>
              <div class="stat"><strong>Blocked</strong><br>{report['summary']['blocked_requests']}</div>
              <div class="stat"><strong>Flagged</strong><br>{report['summary']['flagged_requests']}</div>
              <div class="stat"><strong>Suspicious Sessions</strong><br>{report['summary']['suspicious_sessions']}</div>
            </div>

            <h2>Top Blocked Patterns</h2>
            <ul>{blocked_patterns}</ul>

            <h2>DPDP Mapping</h2>
            <table>
              <thead>
                <tr>
                  <th>Section</th>
                  <th>Obligation</th>
                  <th>System Feature</th>
                  <th>Audit Evidence</th>
                </tr>
              </thead>
              <tbody>{dpdp_rows}</tbody>
            </table>

            <h2>Session Anomalies</h2>
            <table>
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Risky Requests</th>
                  <th>Blocked Requests</th>
                  <th>Cooldown Active</th>
                </tr>
              </thead>
              <tbody>{session_rows}</tbody>
            </table>
          </body>
        </html>
        """

    def _filter_records(
        self,
        records: List[Dict[str, Any]],
        from_ts: Optional[str],
        to_ts: Optional[str],
    ) -> List[Dict[str, Any]]:
        filtered = list(records)
        if from_ts:
            start = parse_timestamp(from_ts)
            filtered = [record for record in filtered if parse_timestamp(record["timestamp"]) >= start]
        if to_ts:
            end = parse_timestamp(to_ts)
            filtered = [record for record in filtered if parse_timestamp(record["timestamp"]) <= end]
        return filtered

    def _build_summary(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        action_counts = Counter(record.get("action_taken", "PASS") for record in records)
        threat_scores = [int(record.get("threat_score", 0)) for record in records]
        suspicious_sessions = self._session_anomalies(records)

        return {
            "total_requests": len(records),
            "blocked_requests": action_counts.get("BLOCK", 0) + action_counts.get("BAN", 0),
            "flagged_requests": action_counts.get("FLAG", 0),
            "clean_requests": action_counts.get("PASS", 0),
            "suspicious_sessions": len(suspicious_sessions),
            "avg_threat_score": round(sum(threat_scores) / len(threat_scores), 1) if threat_scores else 0,
        }

    def _top_patterns(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pattern_counter = Counter()
        for record in records:
            if record.get("action_taken") in {"BLOCK", "BAN"}:
                pattern_counter.update(record.get("injection_signals", []))

        return [
            {"pattern": pattern, "count": count}
            for pattern, count in pattern_counter.most_common(10)
        ]

    def _session_anomalies(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies: Dict[str, Dict[str, Any]] = {}
        for record in records:
            session_state = record.get("session_state") or {}
            session_id = record.get("session_id")
            if not session_id:
                continue
            if not (session_state.get("suspicious") or session_state.get("cooldown_active")):
                continue

            anomalies[session_id] = {
                "session_id": session_id,
                "risky_request_count": session_state.get("risky_request_count", 0),
                "blocked_request_count": session_state.get("blocked_request_count", 0),
                "cooldown_active": session_state.get("cooldown_active", False),
                "cooldown_remaining_seconds": session_state.get("cooldown_remaining_seconds", 0),
            }

        return list(anomalies.values())[:20]

    def _report_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "request_id": record.get("request_id"),
            "timestamp": record.get("timestamp"),
            "session_id": record.get("session_id"),
            "risk_level": record.get("risk_level"),
            "threat_score": record.get("threat_score"),
            "action_taken": record.get("action_taken"),
            "provider": record.get("provider"),
            "sql_intent_token": record.get("sql_intent_token"),
            "injection_signals": record.get("injection_signals", []),
            "pii_redactions": record.get("pii_redactions", {}),
            "compliance_tags": record.get("compliance_tags", []),
        }
