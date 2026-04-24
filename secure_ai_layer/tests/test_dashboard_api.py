import os
from pathlib import Path

from fastapi.testclient import TestClient

from src.config.config_loader import update_active_policy
from src.main import app, event_broadcaster, session_store
from tests.helpers import write_policy as write_test_policy


def write_policy(path: Path) -> None:
    write_test_policy(
        path,
        {
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
        },
    )


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
        blocked_detail = blocked_response.json()["detail"]
        assert blocked_detail["block_explanation"]
        assert "intent_source" in blocked_detail

        summary_response = client.get("/dashboard/summary")
        summary = summary_response.json()
        assert summary["totals"]["total_requests"] == 2
        assert summary["totals"]["blocked_requests"] == 1
        assert summary["totals"]["clean_requests"] == 1
        assert summary["recent_records"][0]["risk_level"] == "RED"
        assert summary["recent_records"][1]["provider"] == "openai"
        assert "intent_source" in summary["recent_records"][0]


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


def test_dashboard_incidents_clusters_flagged_and_blocked_traffic(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))

    with TestClient(app) as client:
        client.post("/demo/simulate", json={"scenario_id": "prompt_injection", "session_id": "cluster-a"})
        client.post("/demo/simulate", json={"scenario_id": "prompt_injection", "session_id": "cluster-b"})
        client.post("/demo/simulate", json={"scenario_id": "base64_attack", "session_id": "cluster-c"})

        incidents_response = client.get("/dashboard/incidents")

    assert incidents_response.status_code == 200
    body = incidents_response.json()
    assert body["count"] >= 1
    first_incident = body["incidents"][0]
    assert "incident_id" in first_incident
    assert first_incident["event_count"] >= 1
    assert "severity_score" in first_incident
    assert "top_signals" in first_incident
    assert "related_request_ids" in first_incident


def test_dashboard_incident_records_drilldown_returns_cluster_records(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))

    with TestClient(app) as client:
        client.post("/demo/simulate", json={"scenario_id": "prompt_injection", "session_id": "cluster-a"})
        client.post("/demo/simulate", json={"scenario_id": "prompt_injection", "session_id": "cluster-b"})

        incidents_response = client.get("/dashboard/incidents")
        incident = incidents_response.json()["incidents"][0]

        drilldown_response = client.get(f"/dashboard/incidents/{incident['incident_id']}/records")

    assert drilldown_response.status_code == 200
    drilldown = drilldown_response.json()
    assert drilldown["incident_id"] == incident["incident_id"]
    assert drilldown["count"] >= 1
    assert drilldown["records"][0]["request_id"] in incident["related_request_ids"]
    assert drilldown["records"][0]["incident_family"] == incident["family"]


def test_dashboard_copilot_query_returns_grounded_response(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "audit.db"
    write_policy(policy_path)
    update_active_policy(str(policy_path))
    reset_runtime_state()

    monkeypatch.setenv("POLICY_FILE_PATH", str(policy_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))

    with TestClient(app) as client:
        client.post("/demo/simulate", json={"scenario_id": "prompt_injection", "session_id": "cluster-a"})
        client.post("/demo/simulate", json={"scenario_id": "base64_attack", "session_id": "cluster-b"})

        incidents_response = client.get("/dashboard/incidents")
        incident = incidents_response.json()["incidents"][0]

        copilot_response = client.post(
            "/dashboard/copilot/query",
            json={
                "question": "Why did blocked traffic spike?",
                "family": incident["family"],
                "incident_id": incident["incident_id"],
            },
        )

    assert copilot_response.status_code == 200
    body = copilot_response.json()
    assert body["answer"]
    assert body["grounding"]["record_count"] >= 1
    assert body["grounding"]["incident_count"] >= 1
    assert body["cited_incidents"][0]["incident_id"] == incident["incident_id"]
    assert body["cited_records"]
