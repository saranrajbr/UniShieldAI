import time

from app.core.config import settings
from app.schemas.alert import AlertCreate


class AlertDeduplicator:
    """Suppresses repeated alerts to the same target within a window.

In a spoofed SYN/volumetric flood each packet looks like a NEW source, so
keying on source IP alone would raise one alert per packet. Instead we key on
the TARGET, so a flood collapses to one alert whose evidence carries an
aggregation summary (unique sources, total flows, packets). Re-evaluation only
after the window elapses also acts as a periodic "attack still ongoing" beat.
"""

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

    def last_emitted_at(self, alert: AlertCreate, fingerprint: str) -> float | None:
        return self._last_seen.get(_key(alert, fingerprint))

    def record(self, alert: AlertCreate, _fingerprint: str) -> None:
        self._last_seen[_key(alert, _fingerprint)] = time.time()

    def clear(self) -> None:
        self._last_seen.clear()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_sec * 2
        self._last_seen = {k: v for k, v in self._last_seen.items() if v >= cutoff}

    @property
    def suppressed_count(self) -> int:
        return self._suppressed


def _key(alert, fingerprint: str) -> tuple:
    # Target-focused dedup: a spoofed flood is ONE ongoing event toward the
    # victim, not one alert per spoofed source IP.
    return (
        alert.dst_ip,
        alert.protocol,
        alert.threat_type,
        alert.severity,
    )