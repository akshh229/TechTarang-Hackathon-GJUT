import re
import spacy
from typing import Tuple, Dict

class EgressRedactor:
    """
    Scans egress text responses (e.g. LLM outputs) to redact highly sensitive PII.
    """
    def __init__(self):
        # spaCy used for NER if we want fuzzy/name matching.
        # Strict Regex is used for structured identifiers (PAN, Aadhaar).
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            self.nlp = None

    def redact(self, text: str) -> Tuple[str, Dict[str, int]]:
        from src.config.config_loader import get_policy_config
        config = get_policy_config()
        pii_patterns = config.get("pii_patterns", {})
        
        redacted_text = text
        stats = {"pan": 0, "aadhaar": 0, "email": 0, "phone": 0}
        
        # PAN format: 5 letters, 4 numbers, 1 letter
        if pii_patterns.get("pan"):
            pan_re = re.compile(pii_patterns["pan"])
            matches = pan_re.findall(redacted_text)
            if matches:
                stats["pan"] += len(matches)
                redacted_text = pan_re.sub("[PAN REDACTED]", redacted_text)
                
        # Aadhaar format: 12 digits (space optional)
        if pii_patterns.get("aadhaar"):
            aadhaar_re = re.compile(pii_patterns["aadhaar"])
            matches = aadhaar_re.findall(redacted_text)
            if matches:
                stats["aadhaar"] += len(matches)
                redacted_text = aadhaar_re.sub("[AADHAAR REDACTED]", redacted_text)
                
        # Email format
        if pii_patterns.get("email"):
            email_re = re.compile(pii_patterns["email"], re.IGNORECASE)
            matches = email_re.findall(redacted_text)
            if matches:
                stats["email"] += len(matches)
                redacted_text = email_re.sub("[EMAIL REDACTED]", redacted_text)
                
        # Phone format
        if pii_patterns.get("phone"):
            phone_re = re.compile(pii_patterns["phone"])
            matches = phone_re.findall(redacted_text)
            if matches:
                stats["phone"] += len(matches)
                redacted_text = phone_re.sub("[PHONE REDACTED]", redacted_text)
                
        return redacted_text, stats
