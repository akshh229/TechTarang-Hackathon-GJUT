import asyncio
from collections import deque
from typing import Any, Deque, Dict, List

from fastapi import WebSocket


class EventBroadcaster:
    """Tracks websocket connections and broadcasts telemetry updates."""

    def __init__(self, max_events: int = 50):
        self.max_events = max_events
        self._connections: List[WebSocket] = []
        self._recent_events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, event: Dict[str, Any]) -> None:
        self._recent_events.append(event)

        stale_connections: List[WebSocket] = []
        async with self._lock:
            for connection in list(self._connections):
                try:
                    await connection.send_json(event)
                except Exception:
                    stale_connections.append(connection)

            for connection in stale_connections:
                if connection in self._connections:
                    self._connections.remove(connection)

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._recent_events)

    def reset(self) -> None:
        self._recent_events.clear()
        self._connections.clear()
