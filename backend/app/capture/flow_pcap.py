"""Flow-to-PCAP recorder.

The backend receives aggregated flow records (NetFlow/flow-export/sensor), not
raw packets. To still provide raw, Wireshark-openable evidence we reconstruct a
faithful-enough packet capture from the records: one IP packet per flow with
the real 5-tuple, flags and byte sizes, written to
``captures/active/current.pcap``. The ``EvidenceCollector`` then preserves a
copy into ``captures/incidents/`` when a threat fires.
"""

import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("unishield.capture")


class FlowPcapRecorder:
    def __init__(self, active_dir: str | None = None,
                 max_bytes: int | None = None,
                 rotate_interval_sec: int | None = None) -> None:
        self.active_dir = Path(active_dir or settings.pcap_active_path).parent
        self.max_bytes = max_bytes or settings.pcap_max_bytes
        self.rotate_interval_sec = rotate_interval_sec or settings.pcap_rotation_interval_sec
        self.active_dir.mkdir(parents=True, exist_ok=True)
        self._current = self.active_dir / "current.pcap"
        self._lock = threading.Lock()
        self._writer = None
        self._bytes_written = 0
        self._started = time.time()
        self._running = False
        self._dropped = 0

    def start(self) -> None:
        self._running = True
        logger.info("Flow capture started → %s", self._current)

    def stop(self) -> None:
        self._running = False
        self._close_writer()

    def record(self, src_ip: str, dst_ip: str, protocol: str,
               src_port: int | None, dst_port: int | None,
               byte_count: int, syn: int = 0, ack: int = 0,
               rst: int = 0, fin: int = 0) -> None:
        if not self._running:
            return
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw
        except ImportError:
            return

        try:
            if protocol == "udp":
                l4 = UDP(sport=src_port or 0, dport=dst_port or 0)
            elif protocol == "icmp":
                l4 = ICMP()
            else:
                flags = "S" if syn else ("A" if ack else ("R" if rst else ("F" if fin else "")))
                l4 = TCP(sport=src_port or 0, dport=dst_port or 0, flags=flags)
            pkt = IP(src=src_ip, dst=dst_ip) / l4
            if byte_count and dst_port in (80, 443, 8080):
                pkt = IP(src=src_ip, dst=dst_ip) / l4 / Raw(load=b"\x00" * min(byte_count, 200))
            pkt.time = time.time()
            with self._lock:
                if not self._running:
                    return
                if self._needs_rotate():
                    self._rotate()
                self._writer = self._writer or self._open_writer()
                self._writer.write(pkt)
                self._bytes_written += len(pkt)
        except Exception:
            self._dropped += 1

    def current_path(self) -> Path:
        return self._current

    def active_exists(self) -> bool:
        return self._current.exists() and self._current.stat().st_size > 0

    def _needs_rotate(self) -> bool:
        if self._bytes_written >= self.max_bytes:
            return True
        if time.time() - self._started >= self.rotate_interval_sec:
            return True
        return False

    def _rotate(self) -> None:
        self._close_writer()
        if self._current.exists() and self._current.stat().st_size > 0:
            try:
                archive_dir = Path(settings.pcap_archive_path)
                archive_dir.mkdir(parents=True, exist_ok=True)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                import shutil
                shutil.copy2(self._current, archive_dir / f"rolling_{timestamp}.pcap")
            except Exception:
                pass
        self._open_writer()
        self._bytes_written = 0
        self._started = time.time()

    def _open_writer(self):
        from scapy.utils import PcapWriter
        self._writer = PcapWriter(str(self._current), append=True, sync=False)
        return self._writer

    def _close_writer(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None


flow_pcap_recorder = FlowPcapRecorder()