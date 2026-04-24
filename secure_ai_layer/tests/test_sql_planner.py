import pytest
import os
import tempfile
import yaml
import asyncio

from src.config.config_loader import update_active_policy
from src.sql_planner.planner import SQLPlanner

from tests.helpers import make_policy

@pytest.fixture(autouse=True)
def setup_policy():
    policy = make_policy(
        {
            "sql_policy": {
                "templates": {
                    "GET_ACCOUNT_BALANCE": "SELECT balance FROM accounts WHERE user_id = :user_id",
                    "GET_USER_PROFILE": "SELECT name, email, phone FROM users WHERE user_id = :user_id",
                }
            }
        }
    )
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        yaml.safe_dump(policy, f)
        filepath = f.name

    update_active_policy(filepath)
    yield
    os.unlink(filepath)

def test_intent_classification():
    planner = SQLPlanner()
    intent = planner.classify_intent("Tell me my account balance")
    assert intent == "GET_ACCOUNT_BALANCE"
    
    intent2 = planner.classify_intent("Can I see my profile details?")
    assert intent2 == "GET_USER_PROFILE"

def test_ai_intent_classification_falls_back_to_rules_without_json():
    planner = SQLPlanner()
    result = asyncio.run(planner.classify_intent_with_metadata("Tell me my account balance"))
    assert result["intent"] == "GET_ACCOUNT_BALANCE"
    assert result["intent_source"] in {"rule", "ai_fallback"}
    assert result["intent_confidence"] >= 0.72 or result["intent_source"] != "ai"

def test_render_query():
    planner = SQLPlanner()
    sql = planner.render_query("GET_ACCOUNT_BALANCE", {"user_id": "123"})
    assert sql == "SELECT balance FROM accounts WHERE user_id = :user_id"

def test_render_unknown_query():
    planner = SQLPlanner()
    with pytest.raises(ValueError, match="Policy violation"):
        planner.render_query("HACK_THE_DB", {"user_id": "123"})
