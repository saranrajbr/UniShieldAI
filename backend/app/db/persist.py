import json

from app.core.logging import get_logger
from app.db.alert_repository import AlertRepository
from app.db.database import SessionLocal
from app.db.metrics_repository import MetricsRepository
from app.models.database_models import DetectionRecord
from app.schemas.metrics import TrafficStats
from app.utils.metrics import runtime_metrics

logger = get_logger("unishield.persist")


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