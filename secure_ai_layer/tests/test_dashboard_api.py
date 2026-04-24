import os
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from src.config.config_loader import update_active_policy
from src.main import app, event_broadcaster, session_store


def write_policy(path: Path) -> None:
    policy = {
        "llm": {"provider": "openai", "model": "gpt-4.1-mini"},
        "dashboard": {"latency_threshold_ms": 150},
        "session_policy": {
            "suspicious_window_seconds": 300,
            "suspicious_min_requests": 3,
            "cooldown_window_seconds": 600,
            "cooldown_blocks": 2,
            "cooldown_duration_seconds": 60,
        },
        "sql_policy": {
            "templates": {
                "GET_ACCOUNT_BALANCE": "SELECT balance FROM accounts WHERE user_id = :user_id"
            }
        },
        "injection_rules": [
            {"pattern": "ignore all previous instructions", "severity": "CRITICAL"},
            {"pattern": "dump the users table", "severity": "CRITICAL"},
            {"pattern": "system prompt", "severity": "HIGH"},
        ],
        "pii_patterns": {
            "pan": "[A-Z]{5}[0-9]{4}[A-Z]{1}",
            "aadhaar": "\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b",
            "email": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
            "phone": "\\+?\\d{10,13}",
        },
        "risk_thresholds": {"amber": 30, "red": 60},
    }
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")


def reset_runtime_state() -> None:
    event_broadcaster.reset()
    session_store.reset()


def test_dashboard_summary_updates_after_simulation(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))

    with TestClient(app) as client:
        initial_summary = client.get("/dashboard/summary")
        assert initial_summary.status_code == 200
        assert initial_summary.json()["totals"]["total_requests"] == 0

        simulate_response = client.post("/demo/simulate", json={"scenario_id": "benign_balance"})
        assert simulate_response.status_code == 200
        assert simulate_response.json()["metadata"]["action_taken"] == "PASS"

        blocked_response = client.post("/demo/simulate", json={"scenario_id": "prompt_injection"})
        assert blocked_response.status_code == 403

        summary_response = client.get("/dashboard/summary")
        summary = summary_response.json()
        assert summary["totals"]["total_requests"] == 2
        assert summary["totals"]["blocked_requests"] == 1
        assert summary["totals"]["clean_requests"] == 1
        assert summary["recent_records"][0]["risk_level"] == "RED"
        assert summary["recent_records"][1]["provider"] == "openai"


def test_websocket_receives_live_telemetry(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))

    with TestClient(app) as client:
        with client.websocket_connect("/ws/events") as websocket:
            bootstrap = websocket.receive_json()
            assert bootstrap["type"] == "bootstrap"

            response = client.post("/demo/simulate", json={"scenario_id": "benign_balance"})
            assert response.status_code == 200

            event = websocket.receive_json()
            assert event["type"] == "telemetry"
            assert event["payload"]["action_taken"] == "PASS"
            assert event["payload"]["provider"] == "openai"
