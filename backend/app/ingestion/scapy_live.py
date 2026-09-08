"""Live Scapy sniffing source that yields FlowRecords from an interface.

The on-Laptop-2 sensor uses this to turn mirrored packets on the tap/SPAN
NIC into flow records, which `LiveCapture` then POSTs to the backend on
Laptop 1 over the WireGuard tunnel. This mirrors `ScapyParser` so the flow
semantics are identical to offline replay and the synthetic training source.
"""

import asyncio
from collections import defaultdict
from datetime import datetime, timezone

from app.ingestion.base import FlowSourceBase
from app.schemas.traffic import FlowRecord


class ScapyLiveSource(FlowSourceBase):
    name = "scapy_live"

    def __init__(self, interface: str, aggregation_window: float = 1.0) -> None:
        self.interface = interface
        self.aggregation_window = aggregation_window
        self._running = False

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def read(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
        except ImportError:
            return

        window_meta: dict[tuple, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "ts": None, "dns": None, "ja3": None}
        )

        while self._running:
            try:
                pkts = await asyncio.to_thread(
                    sniff, iface=self.interface, count=500, timeout=1, store=True
                )
                for pkt in pkts:
                    if pkt is None or IP not in pkt:
                        continue
                    ip = pkt[IP]
                    protocol = "tcp"
                    s_port = d_port = None
                    dns_qname: str | None = None
                    tls_payload: bytes | None = None
                    if TCP in pkt:
                        s_port, d_port = pkt[TCP].sport, pkt[TCP].dport
                        if d_port == 443 and Raw in pkt:
                            tls_payload = bytes(pkt[Raw].load)
                    elif UDP in pkt:
                        protocol = "udp"
                        s_port, d_port = pkt[UDP].sport, pkt[UDP].dport
                        if s_port == 53:
                            from app.ingestion.scapy import _extract_dns_qname
                            dns_qname = _extract_dns_qname(pkt)
                    elif ICMP in pkt:
                        protocol = "icmp"
                    ts = float(pkt.time)
                    key = (ip.src, ip.dst, s_port, d_port, protocol)
                    meta = window_meta[key]
                    meta["packets"] += 1
                    meta["bytes"] += len(pkt)
                    meta["ts"] = ts if meta["ts"] is None else min(meta["ts"], ts)
                    if tls_payload is not None and meta["ja3"] is None:
                        from app.ingestion.tls import extract_ja3
                        meta["ja3"] = extract_ja3(tls_payload)
                    if dns_qname is not None and meta["dns"] is None:
                        meta["dns"] = dns_qname

                for key, meta in list(window_meta.items()):
                    if meta["packets"] > 0:
                        yield self._to_record(meta, key)
                window_meta.clear()
            except Exception:
                await asyncio.sleep(0.5)

    def _to_record(self, meta: dict, key: tuple) -> FlowRecord:
        src_ip, dst_ip, src_port, dst_port, protocol = key
        return FlowRecord(
            ts=datetime.fromtimestamp(meta["ts"], tz=timezone.utc)
            if meta["ts"]
            else datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=meta["packets"],
            byte_count=meta["bytes"],
            dns_query=meta.get("dns"),
            tls_ja3=meta.get("ja3"),
        )