import time
from datetime import datetime, timezone
from typing import Sequence


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_epoch() -> float:
    return time.time()


def to_epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def from_epoch(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def iso8601(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat()


def elapsed_seconds(start_ts: float) -> float:
    return max(0.0, now_epoch() - start_ts)


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 1:
        return "<1s"
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes}m"


def rolling_average(values: Sequence[float], window: int = 5) -> float:
    if not values:
        return 0.0
    sample = values[-window:]
    return sum(sample) / len(sample)


def rate_per_second(count: int, window_seconds: float) -> float:
    if window_seconds <= 0:
        return 0.0
    return count / window_seconds