import jinja2
from typing import Dict, Any

from src.ai.intent_classifier import IntentClassifier
from src.ai.schemas import IntentClassificationResult
from src.config.config_loader import get_policy_config

class SQLPlanner:
    """
    Policy-Aware SQL Planner:
    1. Classifies natural language intent into an approved SQL intent token.
    2. Renders parameterised SQL queries using Jinja2 securely based on policy templates.
    """
    def __init__(self):
        # We don't want Jinja autoescape for raw SQL as it escapes DB chars, 
        # BUT we must parameterise correctly. 
        # In a real DB setup we would use bound parameters (?), not string interpolation.
        # For the hackathon prototype, we will just use Jinja2 to render the safe string token.
        self.jinja_env = jinja2.Environment()

    def _classify_intent_rules(self, text: str) -> str:
        text_lower = text.lower()
        if "balance" in text_lower or "money" in text_lower:
            return "GET_ACCOUNT_BALANCE"
        if "transaction" in text_lower or "recent" in text_lower:
            return "GET_RECENT_TRANSACTIONS"
        if "profile" in text_lower or "my details" in text_lower:
            return "GET_USER_PROFILE"
        if "update" in text_lower and "contact" in text_lower:
            return "UPDATE_CONTACT_INFO"
        if "loan" in text_lower or "mortgage" in text_lower:
            return "GET_LOAN_STATUS"
        return "UNKNOWN_INTENT"

    def classify_intent(self, text: str) -> str:
        """
        Rule engine to map intent. In a full system, this would call an LLM (Intent Classifier prompt).
        """
        return self._classify_intent_rules(text)

    async def classify_intent_with_metadata(
        self,
        text: str,
        provider_override: str | None = None,
    ) -> Dict[str, Any]:
        config = get_policy_config()
        templates = config.get("sql_policy", {}).get("templates", {})
        allowed_intents = list(templates.keys())
        fallback_intent = self._classify_intent_rules(text)

        metadata: Dict[str, Any] = {
            "intent": fallback_intent,
            "intent_source": "rule",
            "intent_confidence": 1.0 if fallback_intent != "UNKNOWN_INTENT" else 0.35,
            "extracted_entities": {},
            "intent_rationale": "Rule-based keyword classifier.",
        }

        classifier_config = config.get("intent_classifier", {})
        if not classifier_config.get("enabled", True):
            return metadata

        classifier = IntentClassifier.from_config(config)
        try:
            result: IntentClassificationResult = await classifier.classify(
                text,
                allowed_intents,
                provider_override=provider_override,
                model=classifier_config.get("model") or config.get("llm", {}).get("model"),
            )
        except Exception:
            return metadata

        if result.confidence < classifier.min_confidence:
            metadata["intent_source"] = "ai_fallback"
            metadata["intent_confidence"] = float(result.confidence)
            metadata["intent_rationale"] = result.rationale or "AI confidence below threshold; used rule fallback."
            return metadata

        return {
            "intent": result.intent,
            "intent_source": "ai",
            "intent_confidence": float(result.confidence),
            "extracted_entities": result.extracted_entities,
            "intent_rationale": result.rationale,
        }

    def render_query(self, intent: str, params: Dict[str, Any]) -> str:
        """
        Renders the query from the policy file instead of trusting the LLM.
        """
        config = get_policy_config()
        templates = config.get("sql_policy", {}).get("templates", {})
        
        template_str = templates.get(intent)
        if not template_str:
            raise ValueError(f"Policy violation: No explicit template configured for intent '{intent}'")
            
        template = self.jinja_env.from_string(template_str)
        rendered_sql = template.render(**params)
        return rendered_sql
