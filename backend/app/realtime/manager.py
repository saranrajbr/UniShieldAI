import asyncio
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> int:
        stale: list[WebSocket] = []
        sent = 0
        async with self._lock:
            connections = list(self._connections)
        for websocket in connections:
            try:
                await websocket.send_json(message)
                sent += 1
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            await self.disconnect(websocket)
        return sent

    @property
    def active_count(self) -> int:
        return len(self._connections)


connection_manager = ConnectionManager()