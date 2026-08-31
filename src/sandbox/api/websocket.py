from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = structlog.get_logger()

router = APIRouter()


class EventBroadcaster:
    """Fan-out pipeline events to all connected WebSocket clients."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._history: list[dict[str, Any]] = []
        self._max_history = 500

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)
        logger.info("ws_client_connected", total=len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)
        logger.info("ws_client_disconnected", total=len(self._clients))

    async def broadcast(self, event: dict[str, Any]) -> None:
        event.setdefault("timestamp", time.time())
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        dead: list[WebSocket] = []
        for ws in self._clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._history[-limit:]


broadcaster = EventBroadcaster()


@router.websocket("/ws/events")
async def websocket_events(ws: WebSocket) -> None:
    await broadcaster.connect(ws)
    try:
        for event in broadcaster.recent_events(20):
            await ws.send_json(event)

        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.disconnect(ws)
