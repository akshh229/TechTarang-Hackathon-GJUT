"""Backward-compatible wrapper around the current session store."""

from src.session_store.store import SessionStore

session_store_instance = SessionStore()

__all__ = ["SessionStore", "session_store_instance"]
