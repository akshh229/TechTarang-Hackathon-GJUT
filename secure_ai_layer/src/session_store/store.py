from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, DefaultDict, Dict, List


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionStore:
    """Tracks risky request history for session-level anomaly detection."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self._lock = threading.Lock()
        self._sessions: DefaultDict[str, Dict[str, Any]] = defaultdict(
            lambda: {"events": [], "cooldown_until": None}
        )
        self._apply_config(config or {})

    def _apply_config(self, config: Dict[str, Any]) -> None:
        session_policy = config.get("session_policy", {})
        self.suspicious_window_seconds = int(session_policy.get("suspicious_window_seconds", 300))
        self.suspicious_min_requests = int(session_policy.get("suspicious_min_requests", 10))
        self.cooldown_window_seconds = int(session_policy.get("cooldown_window_seconds", 600))
        self.cooldown_blocks = int(session_policy.get("cooldown_blocks", 5))
        self.cooldown_duration_seconds = int(session_policy.get("cooldown_duration_seconds", 900))
        self.session_ttl_seconds = int(session_policy.get("session_ttl_seconds", 1800))

    def refresh_config(self, config: Dict[str, Any]) -> None:
        with self._lock:
            self._apply_config(config)

    def _prune(self, session_id: str, now: datetime) -> Dict[str, Any]:
        session = self._sessions[session_id]
        ttl_cutoff = now - timedelta(seconds=self.session_ttl_seconds)
        session["events"] = [event for event in session["events"] if event["timestamp"] >= ttl_cutoff]

        cooldown_until = session.get("cooldown_until")
        if cooldown_until and cooldown_until <= now:
            session["cooldown_until"] = None

        return session

    def _summarize(self, session_id: str, session: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        suspicious_cutoff = now - timedelta(seconds=self.suspicious_window_seconds)
        cooldown_cutoff = now - timedelta(seconds=self.cooldown_window_seconds)

        risky_recent = sum(
            1
            for event in session["events"]
            if event["timestamp"] >= suspicious_cutoff and event["risk_level"] in {"AMBER", "RED"}
        )
        blocked_recent = sum(
            1
            for event in session["events"]
            if event["timestamp"] >= cooldown_cutoff and event["action_taken"] in {"BLOCK", "BAN"}
        )
        cooldown_until = session.get("cooldown_until")
        cooldown_remaining = max(
            0,
            int((cooldown_until - now).total_seconds()) if cooldown_until else 0,
        )

        return {
            "session_id": session_id,
            "risky_request_count": risky_recent,
            "blocked_request_count": blocked_recent,
            "suspicious": risky_recent >= self.suspicious_min_requests,
            "cooldown_active": bool(cooldown_until and cooldown_until > now),
            "cooldown_remaining_seconds": cooldown_remaining,
        }

    def preflight(self, session_id: str, now: datetime | None = None) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock:
            session = self._prune(session_id, now)
            return self._summarize(session_id, session, now)

    def record_event(
        self,
        session_id: str,
        threat_score: int,
        risk_level: str,
        action_taken: str,
        now: datetime | None = None,
    ) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock:
            session = self._prune(session_id, now)
            session["events"].append(
                {
                    "timestamp": now,
                    "threat_score": threat_score,
                    "risk_level": risk_level,
                    "action_taken": action_taken,
                }
            )

            summary = self._summarize(session_id, session, now)
            if summary["blocked_request_count"] >= self.cooldown_blocks:
                session["cooldown_until"] = now + timedelta(seconds=self.cooldown_duration_seconds)
                summary = self._summarize(session_id, session, now)

            return summary

    def active_watchlist(self, limit: int = 5) -> List[Dict[str, Any]]:
        now = utc_now()
        sessions: List[Dict[str, Any]] = []

        with self._lock:
            for session_id in list(self._sessions.keys()):
                session = self._prune(session_id, now)
                summary = self._summarize(session_id, session, now)
                if summary["suspicious"] or summary["cooldown_active"]:
                    sessions.append(summary)

        sessions.sort(
            key=lambda item: (
                item["cooldown_active"],
                item["blocked_request_count"],
                item["risky_request_count"],
            ),
            reverse=True,
        )
        return sessions[:limit]

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
