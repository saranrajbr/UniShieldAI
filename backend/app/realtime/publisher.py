import asyncio
from typing import Any, Awaitable

from app.core.logging import get_logger
from app.realtime.manager import connection_manager

logger = get_logger("unishield.publisher")


class EventPublisher:
    def __init__(self, interval_sec: float = 5.0) -> None:
        self.interval_sec = interval_sec
        self._streams: dict[str, callable] = {}
        self._task: asyncio.Task | None = None

    def register_stream(self, name: str, producer: callable) -> None:
        self._streams[name] = producer

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="event-publisher")
        logger.info("EventPublisher started (%ss interval)", self.interval_sec)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                await self._publish_all()
            except Exception:
                logger.exception("Event publish cycle failed")
            await asyncio.sleep(self.interval_sec)

    async def _publish_all(self) -> None:
        for name, producer in self._streams.items():
            try:
                data = producer()
                if asyncio.iscoroutine(data):
                    data = await data
                await connection_manager.broadcast({"type": name, "data": data})
            except Exception:
                logger.exception("Failed to publish stream %s", name)


event_publisher = EventPublisher()


def publish_payload(event_type: str, payload: Any) -> Awaitable[int]:
    return connection_manager.broadcast({"type": event_type, "data": payload})