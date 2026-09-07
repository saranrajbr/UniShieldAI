import time
import threading
from dataclasses import dataclass, field

from app.core.config import settings


@dataclass
class FlowEntry:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    packets: list[dict] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def add_packet(self, size: int, flags: dict | None = None) -> None:
        now = time.time()
        self.packet_count += 1
        self.byte_count += size
        self.last_seen = now
        self.timestamps.append(now)
        if flags:
            self.syn_count += int(flags.get("syn", 0))
            self.ack_count += int(flags.get("ack", 0))
            self.rst_count += int(flags.get("rst", 0))
            self.fin_count += int(flags.get("fin", 0))
        if len(self.timestamps) > 1000:
            self.timestamps = self.timestamps[-500:]

    def merge_stats(
        self,
        packet_count: int = 0,
        byte_count: int = 0,
        syn_count: int = 0,
        ack_count: int = 0,
        rst_count: int = 0,
        fin_count: int = 0,
        ts: float | None = None,
    ) -> None:
        """Merge an aggregated flow report into this flow's running totals."""
        now = ts if ts is not None else time.time()
        self.packet_count += int(packet_count)
        self.byte_count += int(byte_count)
        self.syn_count += int(syn_count)
        self.ack_count += int(ack_count)
        self.rst_count += int(rst_count)
        self.fin_count += int(fin_count)
        self.last_seen = now
        self.timestamps.append(now)
        if len(self.timestamps) > 1000:
            self.timestamps = self.timestamps[-500:]


class FlowState:
    def __init__(self) -> None:
        self._flows: dict[str, FlowEntry] = {}
        self._lock = threading.Lock()
        self._timeout_sec = settings.flow_timeout_sec

    def get(self, flow_id: str) -> FlowEntry | None:
        with self._lock:
            return self._flows.get(flow_id)

    def get_or_create(self, flow_id: str, src_ip: str, dst_ip: str,
                      src_port: int | None, dst_port: int | None,
                      protocol: str) -> FlowEntry:
        with self._lock:
            entry = self._flows.get(flow_id)
            if entry is None:
                if len(self._flows) >= settings.max_concurrent_flows:
                    self._evict_stale_locked()
                entry = FlowEntry(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                )
                self._flows[flow_id] = entry
            return entry

    def update(
        self,
        entry: FlowEntry,
        size: int = 0,
        flags: dict | None = None,
        packet_count: int = 0,
        byte_count: int = 0,
        syn_count: int = 0,
        ack_count: int = 0,
        rst_count: int = 0,
        fin_count: int = 0,
        ts: float | None = None,
    ) -> None:
        with self._lock:
            if packet_count > 0 or byte_count > 0:
                entry.merge_stats(
                    packet_count=packet_count,
                    byte_count=byte_count,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    rst_count=rst_count,
                    fin_count=fin_count,
                    ts=ts,
                )
            else:
                entry.add_packet(size, flags)

    def snapshot(self) -> dict[str, FlowEntry]:
        with self._lock:
            return dict(self._flows)

    def size(self) -> int:
        with self._lock:
            return len(self._flows)

    def remove(self, flow_id: str) -> FlowEntry | None:
        with self._lock:
            return self._flows.pop(flow_id, None)

    def evict_expired(self, timeout_sec: float | None = None) -> list[FlowEntry]:
        timeout_sec = timeout_sec or self._timeout_sec
        now = time.time()
        expired: list[FlowEntry] = []
        with self._lock:
            expired_ids = [fid for fid, f in self._flows.items() if now - f.last_seen > timeout_sec]
            for fid in expired_ids:
                expired.append(self._flows.pop(fid))
        return expired

    def _evict_stale_locked(self) -> None:
        now = time.time()
        stale = [fid for fid, f in sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)
                 if now - f.last_seen > 10.0]
        for fid in stale[:100]:
            self._flows.pop(fid, None)

    def clear(self) -> None:
        with self._lock:
            self._flows.clear()


flow_state = FlowState()