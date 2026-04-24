import time
from typing import Dict, List

class SessionStore:
    """
    Session Store: tracks request history per session for APT (Advanced Persistent Threat) detection.
    FR-09: Session-Level Anomaly Detection
    """
    def __init__(self):
        # We use simple dictionaries for the prototype.
        # In a real setup, this would be a Redis sorted set with TTL.
        self.store = {}
        self.banned_sessions = {}
        self.block_counts = {}

    def log_suspicious_request(self, session_id: str, score: int, is_block: bool):
        now = time.time()
        
        if session_id not in self.store:
            self.store[session_id] = []
        if session_id not in self.block_counts:
            self.block_counts[session_id] = []
            
        if score >= 30: # AMBER or RED
            self.store[session_id].append(now)
            
        if is_block:
            self.block_counts[session_id].append(now)

    def is_banned(self, session_id: str) -> bool:
        now = time.time()
        # Clean up old bans (15 min cooldown)
        if session_id in self.banned_sessions:
            if now - self.banned_sessions[session_id] > 900:
                del self.banned_sessions[session_id]
            else:
                return True
                
        # 5 blocks in 10 minutes -> ban
        if session_id in self.block_counts:
            self.block_counts[session_id] = [t for t in self.block_counts[session_id] if now - t <= 600]
            if len(self.block_counts[session_id]) >= 5:
                self.banned_sessions[session_id] = now
                return True
                
        return False

    def is_suspicious(self, session_id: str) -> bool:
        """Returns True if session has >= 10 high/med requests in 5 minutes"""
        now = time.time()
        if session_id in self.store:
            self.store[session_id] = [t for t in self.store[session_id] if now - t <= 300]
            return len(self.store[session_id]) >= 10
        return False

# Global instance for the fastAPI app
session_store_instance = SessionStore()
