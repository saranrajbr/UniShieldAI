import asyncio
import time
import logging

from app.core.config import settings
from app.state.flow_state import flow_state
from app.state.connection_tracker import connection_tracker

logger = logging.getLogger("unishield.expiry")


class ExpiryManager:
    def __init__(
        self,
        flow_timeout_sec: float | None = None,
        connection_expiry_sec: float | None = None,
        interval_sec: float = 5.0,
    ) -> None:
        self.flow_timeout_sec = flow_timeout_sec or settings.flow_timeout_sec
        self.connection_expiry_sec = connection_expiry_sec or settings.connection_expiry_sec
        self.interval_sec = interval_sec
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="expiry-manager")
        logger.info("ExpiryManager started (interval=%ss)", self.interval_sec)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("ExpiryManager stopped")

    async def _run(self) -> None:
        while True:
            try:
                self.sweep()
            except Exception:
                logger.exception("Expiry sweep failed")
            await asyncio.sleep(self.interval_sec)

    def sweep(self) -> dict:
        now = time.time()
        stats = {"flows_expired": 0, "connections_expired": 0}

        expired_flows = flow_state.evict_expired(self.flow_timeout_sec)
        stats["flows_expired"] = len(expired_flows)

        for conn in connection_tracker.expiry_candidates(self.connection_expiry_sec):
            connection_tracker.remove(conn.conn_key)
            stats["connections_expired"] += 1

        if stats["flows_expired"] or stats["connections_expired"]:
            logger.debug("Expiry sweep: %s", stats)
        return stats


expiry_manager = ExpiryManager()