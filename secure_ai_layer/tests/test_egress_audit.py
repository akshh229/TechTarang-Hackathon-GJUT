import pytest
import os
import tempfile
import yaml
from pathlib import Path

from fastapi.testclient import TestClient

from src.main import app, event_broadcaster, session_store
from src.audit.logger import AuditLogger
from src.config.config_loader import update_active_policy
from src.egress.redactor import EgressRedactor

from tests.helpers import make_policy

@pytest.fixture(autouse=True)
def setup_policy():
    policy = make_policy()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        yaml.safe_dump(policy, f)
        filepath = f.name

    update_active_policy(filepath)
    yield
    os.unlink(filepath)

def test_egress_redactor():
    redactor = EgressRedactor()
    text = "My PAN is ABCDE1234F and my Aadhaar is 1234 5678 9012. Secret!"
    redacted, stats = redactor.redact(text)
    
    assert "ABCDE1234F" not in redacted
    assert "[PAN REDACTED]" in redacted
    assert stats["pan"] == 1
    
    assert "1234 5678 9012" not in redacted
    assert "[AADHAAR REDACTED]" in redacted
    assert stats["aadhaar"] == 1

def test_audit_logger():
    db_path = "test_audit.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        
    logger = AuditLogger(db_path)
    req_id = logger.log_request({
        "risk_level": "RED",
        "threat_score": 85,
        "injection_signals": ["ignore all"]
    })
    
    records = logger.get_records()
    assert len(records) == 1
    assert records[0]["request_id"] == req_id
    assert records[0]["risk_level"] == "RED"
    assert records[0]["threat_score"] == 85
    
    os.remove(db_path)


def reset_runtime_state() -> None:
    event_broadcaster.reset()
    session_store.reset()


def write_policy(path: Path, overrides=None) -> None:
    policy = make_policy(overrides)
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")


def test_chat_egress_classifier_skips_low_risk_green(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={"user_message": "Show me my account balance for today.", "session_id": "egress-safe"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["metadata"]["egress_label"] == "PASS"
        assert body["metadata"]["egress_recommended_action"] == "allow"
        assert body["metadata"]["egress_was_classified"] is False

        records = client.get("/audit/records").json()["records"]
        assert records[0]["egress_label"] == "PASS"
        assert records[0]["egress_recommended_action"] == "allow"
        assert records[0]["egress_was_classified"] is False


def test_chat_egress_classifier_can_hold_response_for_review(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(
        policy_path,
        {
            "egress_classifier": {
                "enabled": True,
                "risk_threshold": 0,
                "review_labels": ["NEEDS_REVIEW"],
            }
        },
    )
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={"user_message": "Show me my account balance for today.", "session_id": "egress-review"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["metadata"]["egress_label"] == "NEEDS_REVIEW"
        assert body["metadata"]["egress_recommended_action"] == "human_review"
        assert body["metadata"]["egress_reasons"]
        assert "held for operator review" in body["message"].lower()

        records = client.get("/audit/records").json()["records"]
        assert records[0]["egress_label"] == "NEEDS_REVIEW"
        assert records[0]["egress_recommended_action"] == "human_review"
        assert records[0]["egress_reasons"]
