import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone
from typing import Dict, Any, List

class AuditLogger:
    """
    Immutable Append-Only Audit Logger.
    Records every intercepted interaction securely.
    """
    def __init__(self, db_path: str = "audit.db"):
        # Make sure directory exists if given path has one
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            # WAL mode is critical for concurrent FastApi reads (e.g. Dashboard) while streaming writes
            conn.execute("PRAGMA journal_mode=WAL")
            
            # The schema as defined in the PRD FR-04
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    session_id TEXT,
                    input_hash TEXT,
                    input_preview TEXT,
                    sanitized_input_preview TEXT,
                    risk_level TEXT,
                    threat_score INTEGER,
                    injection_signals TEXT,
                    score_breakdown TEXT,
                    sql_intent_token TEXT,
                    provider TEXT,
                    action_taken TEXT,
                    session_state TEXT,
                    pii_redactions TEXT,
                    response_hash TEXT,
                    sanitized_response_preview TEXT,
                    compliance_tags TEXT,
                    latency_ms INTEGER,
                    intent_source TEXT,
                    intent_confidence REAL,
                    block_explanation TEXT,
                    operator_reason TEXT,
                    safe_rewrite TEXT,
                    egress_label TEXT,
                    egress_recommended_action TEXT,
                    egress_reasons TEXT,
                    egress_was_classified INTEGER
                )
            """)
            self._ensure_columns(conn)
            conn.commit()
        finally:
            conn.close()

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        expected_columns = {
            "session_id": "TEXT",
            "input_preview": "TEXT",
            "sanitized_input_preview": "TEXT",
            "score_breakdown": "TEXT",
            "provider": "TEXT",
            "action_taken": "TEXT",
            "session_state": "TEXT",
            "sanitized_response_preview": "TEXT",
            "compliance_tags": "TEXT",
            "intent_source": "TEXT",
            "intent_confidence": "REAL",
            "block_explanation": "TEXT",
            "operator_reason": "TEXT",
            "safe_rewrite": "TEXT",
            "egress_label": "TEXT",
            "egress_recommended_action": "TEXT",
            "egress_reasons": "TEXT",
            "egress_was_classified": "INTEGER",
        }

        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }

        for column_name, column_type in expected_columns.items():
            if column_name not in existing_columns:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column_name} {column_type}")
            
    def log_request(self, record: Dict[str, Any]) -> str:
        """
        Append-only insert logic.
        """
        request_id = str(record.get("request_id", uuid.uuid4()))
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT INTO audit_log (
                    request_id, timestamp, session_id, input_hash, input_preview,
                    sanitized_input_preview, risk_level, threat_score, injection_signals,
                    score_breakdown, sql_intent_token, provider, action_taken,
                    session_state, pii_redactions, response_hash,
                    sanitized_response_preview, compliance_tags, latency_ms,
                    intent_source, intent_confidence, block_explanation, operator_reason, safe_rewrite,
                    egress_label, egress_recommended_action, egress_reasons, egress_was_classified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id,
                record.get("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
                record.get("session_id", ""),
                record.get("input_hash", ""),
                record.get("input_preview", ""),
                record.get("sanitized_input_preview", ""),
                record.get("risk_level", "GREEN"),
                record.get("threat_score", 0),
                json.dumps(record.get("injection_signals", [])),
                json.dumps(record.get("score_breakdown", {})),
                record.get("sql_intent_token", "UNKNOWN_INTENT"),
                record.get("provider", "openai"),
                record.get("action_taken", "PASS"),
                json.dumps(record.get("session_state", {})),
                json.dumps(record.get("pii_redactions", {})),
                record.get("response_hash", ""),
                record.get("sanitized_response_preview", ""),
                json.dumps(record.get("compliance_tags", [])),
                record.get("latency_ms", 0),
                record.get("intent_source", "rule"),
                record.get("intent_confidence", 0.0),
                record.get("block_explanation", ""),
                record.get("operator_reason", ""),
                record.get("safe_rewrite", ""),
                record.get("egress_label", "PASS"),
                record.get("egress_recommended_action", "allow"),
                json.dumps(record.get("egress_reasons", [])),
                1 if record.get("egress_was_classified", False) else 0,
            ))
            conn.commit()
        finally:
            conn.close()
        return request_id

    def get_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
            records = [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

        json_fields = {
            "injection_signals",
            "score_breakdown",
            "session_state",
            "pii_redactions",
            "compliance_tags",
            "egress_reasons",
        }
        parsed_records: List[Dict[str, Any]] = []

        for record in records:
            for field in json_fields:
                raw_value = record.get(field)
                if not raw_value:
                    record[field] = [] if field in {"injection_signals", "compliance_tags"} else {}
                    continue
                try:
                    record[field] = json.loads(raw_value)
                except json.JSONDecodeError:
                    record[field] = raw_value
            parsed_records.append(record)

        return parsed_records
