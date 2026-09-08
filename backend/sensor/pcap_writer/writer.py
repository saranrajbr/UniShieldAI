"""PCAP Writer — optional parallel recording of mirrored traffic.

Writes mirrored traffic to rolling/temporary PCAP files under captures/active/.
Normal traffic is discarded after rolling-window expiry; relevant traffic is
preserved to captures/incidents/ when a threat is detected.
"""

import os
import shutil
import threading
import time
from pathlib import Path

import yaml

from app.core.config import settings


class PcapWriter:
    def __init__(self, active_dir: str | None = None,
                 incidents_dir: str | None = None,
                 max_bytes: int | None = None,
                 rotate_interval_sec: int | None = None) -> None:
        self.active_dir = Path(active_dir or settings.pcap_active_path).parent
        self.incidents_dir = Path(incidents_dir or settings.pcap_incidents_path)
        self.max_bytes = max_bytes or settings.pcap_max_bytes
        self.rotate_interval_sec = rotate_interval_sec or settings.pcap_rotation_interval_sec
        self.active_dir.mkdir(parents=True, exist_ok=True)
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._current = self.active_dir / "current.pcap"
        self._writer = None
        self._bytes_written = 0
        self._started = time.time()
        self._running = False
        self._wt = threading.Thread(target=self._rotation_loop, daemon=True)
        self._rotation_check_interval = 5.0

    def start(self) -> None:
        self._running = True
        self._wt.start()

    def stop(self) -> None:
        self._running = False
        self._close_writer()

    def write(self, raw_packet: bytes) -> int:
        with self._lock:
            if not self._running:
                return 0
            if self._needs_rotate():
                self._rotate()
            self._writer = self._writer or self._open_writer()
            try:
                self._writer.write(raw_packet)
                self._bytes_written += len(raw_packet)
                return len(raw_packet)
            except Exception:
                return 0

    def write_batch(self, packets: list[bytes]) -> int:
        total = 0
        for pkt in packets:
            total += self.write(pkt)
        return total

    def current_path(self) -> Path:
        return self._current

    def preserve_current(self, incident_name: str) -> Path | None:
        with self._lock:
            if not self._current.exists() or self._current.stat().st_size == 0:
                return None
            self._rotate(final=False)
            target = self.incidents_dir / f"{incident_name}.pcap"
            shutil.copy2(self._current, target)
            return target

    def _needs_rotate(self) -> bool:
        if self._bytes_written >= self.max_bytes:
            return True
        if time.time() - self._started >= self.rotate_interval_sec:
            return True
        return False

    def _rotation_loop(self) -> None:
        while self._running:
            time.sleep(self._rotation_check_interval)
            with self._lock:
                if self._needs_rotate() and self._writer is not None:
                    self._rotate()

    def _rotate(self, final: bool = True) -> None:
        self._close_writer()
        if final and self._current.exists() and self._current.stat().st_size > 0:
            archive_dir = Path(settings.pcap_archive_path)
            archive_dir.mkdir(parents=True, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            shutil.copy2(self._current, archive_dir / f"rolling_{timestamp}.pcap")
        self._open_writer()
        self._bytes_written = 0
        self._started = time.time()

    def _open_writer(self, path: Path | None = None):
        path = path or self._current
        try:
            from scapy.utils import PcapWriter

            self._writer = PcapWriter(str(path), append=True, sync=False)
        except ImportError:
            self._writer = _RawPcapWriter(path)
        return self._writer

    def _close_writer(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None


class _RawPcapWriter:
    """Minimal pcap writer used when scapy is not available."""

    GLOBAL_HEADER = bytes([
        0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ])

    def __init__(self, path: Path) -> None:
        self.file = open(path, "ab")
        if self.file.tell() == 0:
            self.file.write(self.GLOBAL_HEADER)

    def write(self, packet: bytes) -> None:
        import struct

        header = struct.pack("<IIII", int(time.time()), 0, len(packet), len(packet))
        self.file.write(header)
        self.file.write(packet)

    def close(self) -> None:
        self.file.close()