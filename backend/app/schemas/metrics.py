from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MetricPoint(BaseModel):
    name: str
    value: Any
    recorded_at: datetime = Field(default_factory=datetime.utcnow)


class TrafficStats(BaseModel):
    flows_total: int = 0
    flows_analyzed: int = 0
    flows_dropped: int = 0
    packets_total: int = 0
    bytes_total: int = 0
    active_connections: int = 0
    threats_detected: int = 0
    fps: float = 0.0


class EngineHealth(BaseModel):
    status: str = "healthy"
    rules_loaded: int = 0
    ml_loaded: bool = False
    queue_size: int = 0
    last_flow_at: datetime | None = None


class SystemMetrics:
    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._history: dict[str, list[MetricPoint]] = {}

    def incr(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    def set_gauge(self, name: str, value: float) -> None:
        self._gauges[name] = value

    def get_counter(self, name: str) -> int:
        return self._counters.get(name, 0)

    def snapshot(self) -> dict[str, Any]:
        return {"counters": dict(self._counters), "gauges": dict(self._gauges)}

    def record(self, name: str, value: Any) -> None:
        self._history.setdefault(name, []).append(MetricPoint(name=name, value=value))
        if len(self._history[name]) > 10000:
            self._history[name] = self._history[name][-5000:]
