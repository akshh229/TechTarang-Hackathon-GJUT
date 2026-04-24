import pytest
import os
import tempfile
import yaml

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
