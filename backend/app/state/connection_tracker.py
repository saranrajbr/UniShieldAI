import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field

from app.utils.time import now_epoch


@dataclass
class ConnectionState:
    conn_key: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    established: bool = False
    first_seen: float = field(default_factory=now_epoch)
    last_seen: float = field(default_factory=now_epoch)
    packet_count: int = 0
    byte_count: int = 0
    flags_seen: set[str] = field(default_factory=set)
    events: deque = field(default_factory=lambda: deque(maxlen=200))


class ConnectionTracker:
    def __init__(self) -> None:
        self._connections: dict[str, ConnectionState] = {}
        self._by_dst_ip: defaultdict[str, set[str]] = defaultdict(set)
        self._by_src_ip: defaultdict[str, set[str]] = defaultdict(set)
        self._lock = threading.Lock()

    @staticmethod
    def conn_key(src_ip: str, dst_ip: str, src_port: int | None,
                 dst_port: int | None, protocol: str) -> str:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"

    def touch(self, src_ip: str, dst_ip: str, src_port: int | None,
              dst_port: int | None, protocol: str, packet_size: int = 0,
              flags: set[str] | None = None) -> ConnectionState:
        key = self.conn_key(src_ip, dst_ip, src_port, dst_port, protocol)
        with self._lock:
            conn = self._connections.get(key)
            if conn is None:
                conn = ConnectionState(
                    conn_key=key, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port, protocol=protocol,
                )
                self._connections[key] = conn
                self._by_dst_ip[dst_ip].add(key)
                self._by_src_ip[src_ip].add(key)
            conn.last_seen = now_epoch()
            conn.packet_count += 1
            conn.byte_count += packet_size
            if flags:
                conn.flags_seen.update(flags)
                if {"syn", "ack"} <= conn.flags_seen:
                    conn.established = True
                conn.events.append({"ts": now_epoch(), "flags": sorted(flags), "size": packet_size})
            return conn

    def get(self, key: str) -> ConnectionState | None:
        with self._lock:
            return self._connections.get(key)

    def connections_for_dst(self, dst_ip: str) -> list[ConnectionState]:
        with self._lock:
            return [self._connections[k] for k in self._by_dst_ip.get(dst_ip, set()) if k in self._connections]

    def connections_for_src(self, src_ip: str) -> list[ConnectionState]:
        with self._lock:
            return [self._connections[k] for k in self._by_src_ip.get(src_ip, set()) if k in self._connections]

    def distinct_dst_ports_for_dst(self, dst_ip: str) -> set[int]:
        with self._lock:
            return {c.dst_port for c in self.connections_for_dst(dst_ip) if c.dst_port is not None}

    def distinct_src_ips_for_dst(self, dst_ip: str) -> set[str]:
        with self._lock:
            return {c.src_ip for c in self.connections_for_dst(dst_ip)}

    def recent_connections_from_src(self, src_ip: str, within_sec: float = 60.0) -> int:
        cutoff = now_epoch() - within_sec
        with self._lock:
            return sum(
                1 for c in self._connections.values()
                if c.src_ip == src_ip and c.last_seen >= cutoff
            )

    def connections_between(self, src_ip: str, dst_ip: str) -> list[ConnectionState]:
        with self._lock:
            return [
                c for c in self._connections.values()
                if c.src_ip == src_ip and c.dst_ip == dst_ip
            ]

    def count_connections(self) -> int:
        with self._lock:
            return len(self._connections)

    def snapshot_all(self) -> list[ConnectionState]:
        with self._lock:
            return list(self._connections.values())

    def active_connections(self, within_sec: float = 60.0) -> int:
        cutoff = now_epoch() - within_sec
        with self._lock:
            return sum(1 for c in self._connections.values() if c.last_seen >= cutoff)

    def expiry_candidates(self, timeout_sec: float = 300.0) -> list[ConnectionState]:
        cutoff = now_epoch() - timeout_sec
        with self._lock:
            return [c for c in self._connections.values() if c.last_seen < cutoff]

    def remove(self, key: str) -> ConnectionState | None:
        with self._lock:
            conn = self._connections.pop(key, None)
            if conn:
                self._by_src_ip.get(conn.src_ip, set()).discard(key)
                self._by_dst_ip.get(conn.dst_ip, set()).discard(key)
            return conn

    def clear(self) -> None:
        with self._lock:
            self._connections.clear()
            self._by_src_ip.clear()
            self._by_dst_ip.clear()


connection_tracker = ConnectionTracker()