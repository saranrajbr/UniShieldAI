import psutil
import time
from dataclasses import dataclass, field


@dataclass
class RuntimeMetrics:
    started_at: float = field(default_factory=time.time)
    flows_processed: int = 0
    alerts_raised: int = 0
    rules_fired: int = 0
    ml_inferences: int = 0
    queue_high_watermark: int = 0
    processing_errors: int = 0
    _window_start: float = field(default_factory=time.time)
    _window_flows: int = 0

    def record_flow(self) -> None:
        self.flows_processed += 1
        self._window_flows += 1

    def flow_rate_fps(self) -> float:
        now = time.time()
        elapsed = max(1e-6, now - self._window_start)
        rate = self._window_flows / elapsed
        if now - self._window_start >= 5.0:
            self._window_start = now
            self._window_flows = 0
        return rate

    def uptime_sec(self) -> float:
        return time.time() - self.started_at

    def record_error(self) -> None:
        self.processing_errors += 1

    def cpu_percent(self) -> float:
        try:
            return psutil.cpu_percent(interval=0.05)
        except Exception:
            return 0.0

    def memory_mb(self) -> float:
        try:
            return psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def snapshot(self) -> dict:
        return {
            "uptime_sec": time.time() - self.started_at,
            "flows_processed": self.flows_processed,
            "alerts_raised": self.alerts_raised,
            "rules_fired": self.rules_fired,
            "ml_inferences": self.ml_inferences,
            "flow_rate_fps": round(self.flow_rate_fps(), 2),
            "cpu_percent": round(self.cpu_percent(), 2),
            "memory_mb": round(self.memory_mb(), 2),
            "queue_high_watermark": self.queue_high_watermark,
            "processing_errors": self.processing_errors,
        }


runtime_metrics = RuntimeMetrics()