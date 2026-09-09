import asyncio
import json

from app.core.logging import get_logger
from app.db.alert_repository import AlertRepository
from app.db.database import SessionLocal
from app.db.metrics_repository import MetricsRepository
from app.models.database_models import DetectionRecord
from app.schemas.metrics import TrafficStats
from app.utils.metrics import runtime_metrics

logger = get_logger("unishield.persist")


class PersistWorker:
    """Serializes alert DB writes onto a single bounded queue + worker.

    The pipeline can raise hundreds of alerts per second during a flood. If each
    opens its own SQLAlchemy session concurrently the connection pool exhausts
    (QueuePool limit reached) and both the write AND the alerts GET endpoint
    time out. One writer drains the queue sequentially so the pool stays calm
    and the SOC UI never dies.
    """

    def __init__(self, maxsize: int = 20000) -> None:
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._task: asyncio.Task | None = None
        self._dropped = 0
        self._written = 0

    def count(self) -> dict:
        return {"queued": self._queue.qsize(), "written": self._written, "dropped": self._dropped}

    async def start(self) -> None:
        self._task = asyncio.create_task(self._drain(), name="alert-persist-worker")
        logger.info("Alert persist worker started")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Alert persist worker stopped")

    def submit(self, ctx) -> bool:
        try:
            self._queue.put_nowait(ctx)
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            logger.warning("Persist queue full — dropping alert write (%d dropped)", self._dropped)
            return False

    async def _drain(self) -> None:
        while True:
            ctx = await self._queue.get()
            try:
                await persist_alert(ctx)
                self._written += 1
            except Exception:
                logger.exception("Persist worker failed on alert")
            finally:
                self._queue.task_done()


persist_worker = PersistWorker()


async def persist_alert(ctx) -> None:
    try:
        async with SessionLocal() as session:
            repo = AlertRepository(session)
            await repo.create(ctx.alert, ctx.alert_id, ctx.pcap_path)
            flow_id = _flow_id_of(ctx)
            if flow_id:
                session.add(DetectionRecord(
                    flow_id=flow_id,
                    risk_score=ctx.alert.risk_score,
                    confidence=ctx.alert.confidence,
                    threat_type=ctx.alert.threat_type,
                    severity=ctx.alert.severity,
                    is_threat=True,
                    evidence_json=json.dumps(ctx.alert.evidence, default=str),
                ))
                await session.commit()
    except Exception:
        logger.exception("Failed to persist alert %s", getattr(ctx, "alert_id", "?"))


async def persist_metrics_snapshot() -> None:
    snap = runtime_metrics.snapshot()
    stats = TrafficStats(
        flows_total=snap["flows_processed"],
        flows_analyzed=snap["flows_processed"],
        packets_total=0,
        bytes_total=0,
        threats_detected=snap["alerts_raised"],
    )
    try:
        async with SessionLocal() as session:
            await MetricsRepository(session).record_snapshot(stats)
    except Exception:
        logger.exception("Failed to persist metrics snapshot")


def _flow_id_of(ctx) -> str | None:
    alert = getattr(ctx, "alert", None)
    if alert is not None and getattr(alert, "flow_ids", None):
        return alert.flow_ids[0]
    evidence = getattr(alert, "evidence", None) or {}
    if isinstance(evidence, dict):
        features = evidence.get("features") or {}
        return features.get("flow_id")
    return None