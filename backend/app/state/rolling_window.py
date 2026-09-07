import time
from collections import deque, defaultdict
import threading


class RollingWindow:
    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._buckets: dict[float, float] = defaultdict(float)
        self._lock = threading.Lock()

    def _trim_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = [ts for ts in self._buckets if ts < cutoff]
        for ts in stale:
            del self._buckets[ts]

    def add(self, amount: float = 1.0, now: float | None = None) -> None:
        now = now or time.time()
        bucket = int(now)
        with self._lock:
            self._buckets[bucket] += amount
            self._trim_locked(now)

    def add_payload(self, timestamps: list[float], amount: float = 1.0) -> None:
        with self._lock:
            for ts in timestamps:
                self._buckets[int(ts)] += amount

    def total(self) -> float:
        now = time.time()
        with self._lock:
            self._trim_locked(now)
            return sum(self._buckets.values())

    def rate_per_second(self) -> float:
        return self.total() / max(1e-9, self.window_seconds)

    def recent_samples(self) -> list[tuple[float, float]]:
        now = time.time()
        with self._lock:
            self._trim_locked(now)
            return sorted((ts, v) for ts, v in self._buckets.items())

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


class SlidingBuffer:
    def __init__(self, maxlen: int = 1000) -> None:
        self._buffer: deque = deque(maxlen=maxlen)

    def push(self, item) -> None:
        self._buffer.append(item)

    def drain(self) -> list:
        items = list(self._buffer)
        self._buffer.clear()
        return items

    def __len__(self) -> int:
        return len(self._buffer)


class RateWindow:
    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._events: deque[float] = deque()

    def record(self, ts: float | None = None) -> None:
        now = ts or time.time()
        cutoff = now - self.window_seconds
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        self._events.append(now)

    def count(self, since: float | None = None) -> int:
        cutoff = since if since is not None else self._events[0] if self._events else time.time()
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)

    def rate(self) -> float:
        return self.count() / max(1e-9, self.window_seconds)