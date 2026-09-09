import time
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
    emitted_at: float = field(default_factory=time.time)
    last_published_at: float = field(default_factory=time.time)


PULSE_INTERVAL_SEC = 2.0


class AlertManager:
    def __init__(self, generator: AlertGenerator | None = None,
                 deduplicator: AlertDeduplicator | None = None) -> None:
        self.generator = generator or AlertGenerator()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self._recent: deque[AlertContext] = deque(maxlen=1000)
        self._active: dict[tuple, AlertContext] = {}
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
        agg_key = self._aggregation_key(alert)
        active = self._active.get(agg_key)

        # Same target still flooding within the dedup window → merge the new
        # source into the existing alert instead of raising a fresh one.
        if active is not None and self.deduplicator.is_suppressed(alert, fingerprint):
            merge_alert_context(active, alert)
            self._pulse(active)
            return None

        if not self.deduplicator.should_emit(alert, fingerprint):
            return None

        alert_id = _alert_id_from(alert)
        alert.evidence.setdefault("aggregation", {
            "source_count": 1,
            "unique_sources": [alert.src_ip],
            "flow_count": 1,
            "packet_count": _entry_packets(alert),
            "window_sec": settings.dedup_window_sec,
        })
        ctx = AlertContext(alert=alert, alert_id=alert_id, fingerprint=fingerprint, pcap_path=pcap_path)
        self._recent.appendleft(ctx)
        self._active[agg_key] = ctx
        self._prune_active()

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

    def _pulse(self, ctx: AlertContext) -> None:
        """Re-broadcast a live pulse for an ongoing, already-emitted alert.

        While a flood continues inside the dedup window it merges into the
        existing context (aggregation counts, fresh timestamp); the UI should
        see that growth in near-real-time rather than nothing until the window
        elapses. Throttled so a 30-fps flood does not flood WebSockets too.
        """
        now = time.time()
        if now - ctx.last_published_at < PULSE_INTERVAL_SEC:
            return
        ctx.last_published_at = now
        for callback in self._publish_callbacks:
            _call_async(callback, ctx)

    @staticmethod
    def _aggregation_key(alert) -> tuple:
        return (alert.dst_ip, alert.protocol, alert.threat_type, alert.severity)

    def _prune_active(self) -> None:
        cutoff = time.time() - self.deduplicator.window_sec
        stale = [k for k, v in self._active.items() if v.emitted_at < cutoff]
        for k in stale:
            self._active.pop(k, None)

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


def merge_alert_context(ctx: AlertContext, incoming: AlertCreate) -> None:
    """Merge a newly-detected flow into an already-emitting alert.

    Floods produce many spoofed source IPs at the same target; instead of a
    new alert per packet we fold the sources into the existing alert's
    evidence aggregation (unique sources, flow count, packet count) and refresh
    the timestamp so the UI always sees the newest activity.
    """
    agg = ctx.alert.evidence.setdefault("aggregation", {
        "source_count": 0,
        "unique_sources": [],
        "flow_count": 0,
        "packet_count": 0,
        "window_sec": 0,
    })
    unique = agg["unique_sources"]
    if ctx.alert.src_ip not in unique:
        unique.append(ctx.alert.src_ip)
    if incoming.src_ip not in unique:
        unique.append(incoming.src_ip)
    agg["unique_sources"] = unique[-64:]
    agg["source_count"] = len(unique)
    agg["flow_count"] += 1
    agg["packet_count"] += int(_entry_packets(incoming) or 1)
    agg["window_sec"] = 300
    ctx.alert.timestamp = incoming.timestamp
    ctx.emitted_at = time.time()


def _entry_packets(alert: AlertCreate) -> int:
    evidence = getattr(alert, "evidence", {}) or {}
    if not isinstance(evidence, dict):
        return 1
    features = evidence.get("features") or {}
    return int(features.get("packet_count", 1) or 1) if isinstance(features, dict) else 1


def _call_async(fn: callable, *args):
    try:
        loop = asyncio.get_running_loop()
        result = fn(*args)
        if asyncio.iscoroutine(result):
            loop.create_task(result)
    except RuntimeError:
        asyncio.create_task(fn(*args))