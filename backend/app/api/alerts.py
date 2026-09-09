from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.alert_repository import AlertRepository
from app.db.database import get_session
from app.engine.pipeline import pipeline
from app.schemas.alert import AlertList, AlertOut

logger = get_logger("unishield.api.alerts")

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("", response_model=AlertList)
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> AlertList:
    repo = AlertRepository(session)
    persisted = await repo.get_recent(limit)

    live = _live_alerts(limit)
    for ctx in live:
        persisted.append(_ctx_to_schema(ctx))

    return AlertList(total=len(persisted), alerts=persisted[:limit])


@router.get("/live", response_model=AlertList)
async def list_live_alerts(limit: int = Query(100, ge=1, le=1000)) -> AlertList:
    alerts = [_ctx_to_schema(ctx) for ctx in pipeline.alert_manager.recent(limit)]
    return AlertList(total=len(alerts), alerts=alerts)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
) -> AlertOut:
    repo = AlertRepository(session)
    alert = await repo.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    repo = AlertRepository(session)
    alert = await repo.mark_resolved(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True, "status": alert.status, "alert_id": alert.alert_id}


def _live_alerts(limit: int):
    return pipeline.alert_manager.recent(limit)


def _ctx_to_schema(ctx) -> AlertOut:
    return AlertOut(
        id=ctx.alert_id,
        alert_id=ctx.alert_id,
        timestamp=ctx.alert.timestamp,
        src_ip=ctx.alert.src_ip,
        dst_ip=ctx.alert.dst_ip,
        protocol=ctx.alert.protocol,
        threat_type=ctx.alert.threat_type,
        severity=ctx.alert.severity,
        confidence=ctx.alert.confidence,
        risk_score=ctx.alert.risk_score,
        evidence=ctx.alert.evidence,
        detection_sources=ctx.alert.detection_sources,
        pcap_path=ctx.pcap_path,
        aggregation=ctx.alert.evidence.get("aggregation", {}),
    )