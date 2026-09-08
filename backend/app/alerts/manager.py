import asyncio
from collections import deque
from dataclasses import dataclass, field

from app.alerts.deduplicator import AlertDeduplicator
from app.alerts.generator import AlertGenerator
from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.alert import AlertCreate

logger = get_logger("unishield.alerts")


@dataclass
class AlertContext:
    alert: AlertCreate
    alert_id: str
    fingerprint: str
    pcap_path: str | None = None


class AlertManager:
    def __init__(self, generator: AlertGenerator | None = None,
                 deduplicator: AlertDeduplicator | None = None) -> None:
        self.generator = generator or AlertGenerator()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self._recent: deque[AlertContext] = deque(maxlen=1000)
        self._publish_callbacks: list[callable] = []
        self._persist_callbacks: list[callable] = []

    def register_publisher(self, callback: callable) -> None:
        self._publish_callbacks.append(callback)

    def register_persister(self, callback: callable) -> None:
        self._persist_callbacks.append(callback)

    def create_alert(self, decision, features, evidence: dict | None = None,
                     pcap_path: str | None = None) -> AlertContext | None:
        alert = self.generator.generate(decision, features, evidence)
        fingerprint = self.generator.fingerprint(alert)
        if not self.deduplicator.should_emit(alert, fingerprint):
            return None

        alert_id = _alert_id_from(alert)
        ctx = AlertContext(alert=alert, alert_id=alert_id, fingerprint=fingerprint, pcap_path=pcap_path)
        self._recent.appendleft(ctx)

        for callback in self._publish_callbacks:
            _call_async(callback, ctx)
        for callback in self._persist_callbacks:
            _call_async(callback, ctx)

        logger.info(
            "Alert emitted %s — %s from %s to %s (risk=%.2f conf=%.2f)",
            alert_id, alert.threat_type, alert.src_ip, alert.dst_ip,
            alert.risk_score, alert.confidence,
        )
        return ctx

    def recent(self, limit: int = 100) -> list[AlertContext]:
        return list(self._recent)[:limit]

    def set_pcap_path(self, alert_id: str, path: str) -> None:
        for ctx in self._recent:
            if ctx.alert_id == alert_id:
                ctx.pcap_path = path
                return

    def stats(self) -> dict:
        return {
            "recent_count": len(self._recent),
            "suppressed": self.deduplicator.suppressed_count,
        }


def _alert_id_from(alert: AlertCreate) -> str:
    import hashlib
    from datetime import datetime, timezone
    seed = f"{alert.src_ip}{alert.dst_ip}{alert.threat_type}{datetime.now(timezone.utc).isoformat()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16].upper()


def _call_async(fn: callable, *args):
    try:
        loop = asyncio.get_running_loop()
        result = fn(*args)
        if asyncio.iscoroutine(result):
            loop.create_task(result)
    except RuntimeError:
        asyncio.create_task(fn(*args))