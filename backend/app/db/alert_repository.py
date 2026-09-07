import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database_models import AlertRecord
from app.schemas.alert import AlertCreate, AlertOut


class AlertRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, alert: AlertCreate, alert_id: str, pcap_path: str | None = None) -> AlertOut:
        record = AlertRecord(
            alert_id=alert_id,
            timestamp=alert.timestamp,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            protocol=alert.protocol,
            threat_type=alert.threat_type,
            severity=alert.severity,
            confidence=alert.confidence,
            risk_score=alert.risk_score,
            evidence=json.dumps(alert.evidence),
            detection_sources=json.dumps(alert.detection_sources),
            pcap_path=pcap_path,
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        return _to_schema(record)

    async def get_recent(self, limit: int = 100) -> list[AlertOut]:
        result = await self._session.execute(
            select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit)
        )
        return [_to_schema(r) for r in result.scalars().all()]

    async def get_by_id(self, alert_id: str) -> AlertOut | None:
        result = await self._session.execute(
            select(AlertRecord).where(AlertRecord.alert_id == alert_id)
        )
        record = result.scalar_one_or_none()
        return _to_schema(record) if record else None

    async def count(self) -> int:
        result = await self._session.execute(select(AlertRecord))
        return len(result.scalars().all())

    async def mark_resolved(self, alert_id: str) -> AlertOut | None:
        result = await self._session.execute(
            select(AlertRecord).where(AlertRecord.alert_id == alert_id)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        record.resolved = True
        record.status = "resolved"
        await self._session.commit()
        await self._session.refresh(record)
        return _to_schema(record)


def _to_schema(record: AlertRecord) -> AlertOut:
    return AlertOut(
        id=str(record.id),
        alert_id=record.alert_id,
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        protocol=record.protocol,
        threat_type=record.threat_type,
        severity=record.severity,
        confidence=record.confidence,
        risk_score=record.risk_score,
        evidence=json.loads(record.evidence or "{}"),
        detection_sources=json.loads(record.detection_sources or "[]"),
        status=record.status,
    )