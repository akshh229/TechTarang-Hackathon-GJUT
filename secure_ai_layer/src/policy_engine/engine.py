from src.policy_engine.sessions import session_store_instance
import numpy as np

class ThreatScoringEngine:
    """
    FR-07: Composite Threat Intelligence Score
    Computes a composite threat score (0-100) using three dimensions.
    """
    def __init__(self):
        self.model = None

    def load_model(self):
        if not self.model:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                print("Warning: sentence_transformers not installed. Semantic score will default to 0.")
                self.model = None

    def compute_score(self, text: str, pattern_score: int, session_id: str) -> dict:
        """
        Computes the composite 0-100 score.
        1. Pattern Max: 40
        2. Session Max: 35
        3. Semantic Max: 25
        """
        # Dimension 1: Pattern Match Severity
        p_score = min(pattern_score, 40)
        
        # Dimension 2: Session Replay
        s_score = 0
        if session_id and session_store_instance.is_suspicious(session_id):
            s_score = 35 # Max out session score if flagged as suspicious
            
        # Dimension 3: Semantic Anomaly
        semantic_score = 0
        self.load_model()
        if self.model:
            # In a real app we encode a robust dataset of benign queries on startup.
            # Here, we measure distance against a static ideal baseline mock for the prototype.
            baseline = self.model.encode("Tell me my account balance and recent transactions")
            current = self.model.encode(text)
            
            # Use L2 norm distance
            dist = np.linalg.norm(baseline - current)
            # Distance bounds typically ~0 to ~2. Scale it proportionally up to 25.
            semantic_score = min(int(dist * 15), 25)
            
        total_score = p_score + s_score + semantic_score
        
        return {
            "total_score": min(total_score, 100),
            "breakdown": {
                "pattern_score": p_score,
                "session_score": s_score,
                "semantic_score": semantic_score
            }
        }
