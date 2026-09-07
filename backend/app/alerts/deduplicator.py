import time

from app.core.config import settings
from app.schemas.alert import AlertCreate


class AlertDeduplicator:
    """Suppresses repeated alerts for the same source/dest/threat within a window."""

    def __init__(self, window_sec: int | None = None) -> None:
        self.window_sec = window_sec or settings.dedup_window_sec
        self._last_seen: dict[tuple, float] = {}
        self._suppressed = 0

    def should_emit(self, alert: AlertCreate, fingerprint: str) -> bool:
        key = _key(alert, fingerprint)
        now = time.time()
        last = self._last_seen.get(key)
        if last is not None and now - last < self.window_sec:
            self._suppressed += 1
            return False
        self._last_seen[key] = now
        if len(self._last_seen) > 10000:
            self._prune(now)
        return True

    def is_suppressed(self, alert: AlertCreate, fingerprint: str) -> bool:
        key = _key(alert, fingerprint)
        now = time.time()
        last = self._last_seen.get(key)
        return last is not None and now - last < self.window_sec

    def clear(self) -> None:
        self._last_seen.clear()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_sec * 2
        self._last_seen = {k: v for k, v in self._last_seen.items() if v >= cutoff}

    @property
    def suppressed_count(self) -> int:
        return self._suppressed


def _key(alert, fingerprint: str) -> tuple:
    return (
        alert.src_ip,
        alert.dst_ip,
        alert.protocol,
        alert.threat_type,
        alert.severity,
        fingerprint[:12],
    )