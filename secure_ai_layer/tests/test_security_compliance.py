from pathlib import Path

from fastapi.testclient import TestClient

from src.config.config_loader import update_active_policy
from src.main import app, event_broadcaster, session_store
from tests.helpers import write_policy


def reset_runtime_state() -> None:
    event_broadcaster.reset()
    session_store.reset()


def configure_runtime(policy_path: Path, monkeypatch, overrides: dict) -> None:
    db_path = policy_path.with_suffix(".db")
    write_policy(policy_path, overrides)
    update_active_policy(str(policy_path))
    reset_runtime_state()
    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))


def test_security_headers_and_rate_limit_are_enforced(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    configure_runtime(
        policy_path,
        monkeypatch,
        {
            "rate_limit": {
                "enabled": True,
                "window_seconds": 60,
                "requests_per_window": 1,
                "exempt_paths": [],
            }
        },
    )

    with TestClient(app) as client:
        first = client.get("/audit/records", headers={"x-forwarded-for": "10.10.10.10"})
        assert first.status_code == 200
        assert first.headers["x-content-type-options"] == "nosniff"
        assert first.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in first.headers["content-security-policy"]

        second = client.get("/audit/records", headers={"x-forwarded-for": "10.10.10.10"})
        assert second.status_code == 429
        assert second.json()["retry_after_seconds"] >= 1
        assert second.headers["x-content-type-options"] == "nosniff"


def test_payload_size_limit_rejects_large_requests(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    configure_runtime(
        policy_path,
        monkeypatch,
        {
            "rate_limit": {"enabled": False},
            "security": {"max_body_bytes": 80, "exempt_paths": []},
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={"user_message": "x" * 500, "session_id": "payload-limit-test"},
            headers={"x-forwarded-for": "10.10.10.11"},
        )

    assert response.status_code == 413
    assert response.json()["max_body_bytes"] == 80


def test_compliance_report_uses_new_reporter_output(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    configure_runtime(
        policy_path,
        monkeypatch,
        {
            "session_policy": {
                "suspicious_min_requests": 1,
                "cooldown_blocks": 2,
                "cooldown_duration_seconds": 60,
            }
        },
    )

    with TestClient(app) as client:
        allowed = client.post(
            "/demo/simulate",
            json={"scenario_id": "benign_balance", "session_id": "compliance-session"},
        )
        assert allowed.status_code == 200

        blocked = client.post(
            "/demo/simulate",
            json={"scenario_id": "prompt_injection", "session_id": "compliance-session"},
        )
        assert blocked.status_code == 403

        report_response = client.get("/compliance/report?format=json")

    assert report_response.status_code == 200
    report = report_response.json()
    assert report["summary"]["total_requests"] == 2
    assert report["summary"]["blocked_requests"] == 1
    assert len(report["dpdp_mapping"]) >= 5
    assert report["top_blocked_patterns"][0]["pattern"] == "ignore all previous instructions"
    assert report["session_anomalies"][0]["session_id"] == "compliance-session"
    assert len(report["records_included"]) == 2
