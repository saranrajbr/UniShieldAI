from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database_models import TrafficMetricRecord
from app.schemas.metrics import TrafficStats


class MetricsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_snapshot(self, stats: TrafficStats) -> None:
        record = TrafficMetricRecord(
            flows_total=stats.flows_total,
            flows_analyzed=stats.flows_analyzed,
            packets_total=stats.packets_total,
            bytes_total=stats.bytes_total,
            threats_detected=stats.threats_detected,
        )
        self._session.add(record)
        await self._session.commit()

    async def latest(self) -> TrafficStats | None:
        result = await self._session.execute(
            TrafficMetricRecord.__table__.select().order_by(
                TrafficMetricRecord.recorded_at.desc()
            ).limit(1)
        )
        row = result.first()
        if row is None:
            return None
        return TrafficStats(
            flows_total=row.flows_total,
            flows_analyzed=row.flows_analyzed,
            packets_total=row.packets_total,
            bytes_total=row.bytes_total,
            threats_detected=row.threats_detected,
        )