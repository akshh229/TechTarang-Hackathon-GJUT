import fitz  # PyMuPDF
import pytesseract
from PIL import Image
import io
import re
import unicodedata
from typing import Dict, Any, Tuple, List
from src.config.config_loader import get_policy_config

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5,
}

class IngressSanitizer:
    """
    Ingress layer responsible for checking all multimodal inputs (Text, Image, PDF)
    against known injection rules and heuristics.
    """
    def __init__(self):
        pass

    def normalize_text(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text or "")

    def match_rules(self, text: str) -> List[Dict[str, Any]]:
        config = get_policy_config()
        rules = config.get("injection_rules", [])
        normalized_text = self.normalize_text(text).lower()
        triggered: List[Dict[str, Any]] = []

        for rule in rules:
            pattern = rule.get("pattern", "").lower()
            if pattern and pattern in normalized_text:
                triggered.append(rule)

        return triggered

    def sanitize_text(self, text: str, rules: List[Dict[str, Any]] | None = None) -> str:
        sanitized = self.normalize_text(text)
        active_rules = rules if rules is not None else self.match_rules(sanitized)

        for rule in active_rules:
            pattern = rule.get("pattern")
            if not pattern:
                continue
            sanitized = re.sub(re.escape(pattern), "[REDACTED INJECTION TOKEN]", sanitized, flags=re.IGNORECASE)

        return re.sub(r"\s{2,}", " ", sanitized).strip()

    def inspect_text(self, text: str) -> Dict[str, Any]:
        normalized_text = self.normalize_text(text)
        triggered = self.match_rules(normalized_text)
        legacy_rule_score = min(
            100,
            sum(SEVERITY_WEIGHTS.get(rule.get("severity", "LOW"), 5) for rule in triggered),
        )

        return {
            "normalized_text": normalized_text,
            "sanitized_text": self.sanitize_text(normalized_text, triggered),
            "triggered_rules": triggered,
            "triggered_patterns": [rule.get("pattern", "") for rule in triggered],
            "legacy_rule_score": legacy_rule_score,
            "pattern_score": min(40, legacy_rule_score),
        }
        
    def check_text(self, text: str) -> Tuple[str, int, List[str]]:
        """
        Checks text against known injection patterns.
        
        Args:
            text (str): The raw text to check.
            
        Returns:
            Tuple[str, int, List[str]]: 
                - risk_level ("GREEN", "AMBER", "RED")
                - threat_score (0-100)
                - triggered_signals (List of matched patterns)
        """
        inspection = self.inspect_text(text)
        threat_score = inspection["legacy_rule_score"]

        # Apply score thresholds
        risk_level = "GREEN"
        config = get_policy_config()
        thresholds = config.get("risk_thresholds", {"amber": 30, "red": 60})
        
        # Cap threat score at 100 for normalization
        threat_score = min(threat_score, 100)
        
        amber_cap = thresholds.get("amber", 30)
        red_cap = thresholds.get("red", 60)
        
        if threat_score >= red_cap:
            risk_level = "RED"
        elif threat_score >= amber_cap:
            risk_level = "AMBER"
            
        return risk_level, threat_score, inspection["triggered_patterns"]

    def check_image(self, image_bytes: bytes) -> Tuple[str, int, List[str]]:
        """
        Runs OCR on an image and checks the extracted text.
        """
        try:
            image = Image.open(io.BytesIO(image_bytes))
            # Basic OCR extraction
            extracted_text = pytesseract.image_to_string(image)
            if not extracted_text.strip():
                return "GREEN", 0, []
            return self.check_text(extracted_text)
        except Exception as e:
            # If an image fails to parse, flag as AMBER to be safe, but typically would return an error
            return "AMBER", 30, [f"Image OCR failed: {str(e)}"]

    def check_pdf(self, pdf_bytes: bytes) -> Tuple[str, int, List[str]]:
        """
        Extracts text from a PDF and checks it.
        """
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            extracted_text = ""
            for page in doc:
                extracted_text += page.get_text()
            if not extracted_text.strip():
                return "GREEN", 0, []
            return self.check_text(extracted_text)
        except Exception as e:
            return "AMBER", 30, [f"PDF extraction failed: {str(e)}"]
