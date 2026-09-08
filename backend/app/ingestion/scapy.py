"""Scapy-based live capture and parsing for controlled testing.

Scapy is used to read packets from an interface or a pcap file and convert
them into FlowRecords. In production the sensor relies on Zeek; Scapy here
serves as the test/controlled capture source.
"""

from collections import defaultdict
from datetime import datetime, timezone

from app.ingestion.base import FlowParserBase
from app.schemas.traffic import FlowRecord


class ScapyParser(FlowParserBase):
    format_name = "scapy"

    def __init__(self, aggregation_window: float = 1.0) -> None:
        self.aggregation_window = aggregation_window

    def parse_payload(self, payload: bytes) -> list[FlowRecord]:
        try:
            from scapy.all import PcapReader, IP, TCP, UDP, ICMP, Raw
        except ImportError:
            return []

        flows: dict[tuple, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "ts": None, "table": {}, "dns": None, "ja3": None}
        )
        window_keys: dict[int, set] = defaultdict(set)

        reader = PcapReader(io_bytes(payload))
        try:
            for i, pkt in enumerate(reader):
                if i > 100000:
                    break
                if pkt is None or IP not in pkt:
                    continue
                self._accumulate(pkt, IP, TCP, UDP, ICMP, Raw, flows, window_keys)
        finally:
            reader.close()

        return [self._to_record(meta, key) for key, meta in flows.items()]

    def parse_pcap_file(self, pcap_path: str) -> list[FlowRecord]:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
        except ImportError:
            return []

        packets = rdpcap(pcap_path)
        flows: dict[tuple, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "ts": None, "table": {}, "dns": None, "ja3": None}
        )
        window_keys: dict[int, set] = defaultdict(set)

        for pkt in packets:
            if pkt is None or IP not in pkt:
                continue
            self._accumulate(pkt, IP, TCP, UDP, ICMP, Raw, flows, window_keys)

        return [self._to_record(meta, key) for key, meta in flows.items()]

    def _accumulate(self, pkt, IP, TCP, UDP, ICMP, Raw, flows, window_keys) -> None:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = "tcp"
        src_port: int | None = None
        dst_port: int | None = None
        flags: dict = {}
        tls_payload: bytes | None = None
        dns_qname: str | None = None

        if TCP in pkt:
            tcp = pkt[TCP]
            protocol = "tcp"
            src_port, dst_port = tcp.sport, tcp.dport
            flags = _tcp_flags(tcp.flags)
            if dst_port == 443 and Raw in pkt:
                tls_payload = bytes(pkt[Raw].load)
        elif UDP in pkt:
            udp = pkt[UDP]
            protocol = "udp"
            src_port, dst_port = udp.sport, udp.dport
            flags = {}
            if src_port == 53:
                dns_qname = _extract_dns_qname(pkt)
        elif ICMP in pkt:
            protocol = "icmp"
            flags = {"type": int(pkt[ICMP].type)}

        size = len(pkt)
        ts = float(pkt.time) if hasattr(pkt, "time") else datetime.now(timezone.utc).timestamp()

        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        win = int(ts // self.aggregation_window)
        window_keys[win].add(key)
        flows[key]["packets"] += 1
        flows[key]["bytes"] += size
        flows[key]["ts"] = ts if flows[key]["ts"] is None else min(ts, flows[key]["ts"])
        flows[key]["table"][win] = flows[key]["table"].get(win, 0) + 1
        if tls_payload and flows[key]["ja3"] is None:
            from app.ingestion.tls import extract_ja3
            flows[key]["ja3"] = extract_ja3(tls_payload)
        if dns_qname and flows[key]["dns"] is None:
            flows[key]["dns"] = dns_qname

    def _to_record(self, meta: dict, key: tuple) -> FlowRecord:
        src_ip, dst_ip, src_port, dst_port, protocol = key
        return FlowRecord(
            ts=datetime.fromtimestamp(meta["ts"], tz=timezone.utc),
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


def _tcp_flags(flags_byte: int) -> dict[str, int]:
    return {
        "syn": int(flags_byte & 0x02 > 0),
        "ack": int(flags_byte & 0x10 > 0),
        "rst": int(flags_byte & 0x04 > 0),
        "fin": int(flags_byte & 0x01 > 0),
        "psh": int(flags_byte & 0x08 > 0),
    }


def _extract_dns_qname(pkt) -> str | None:
    try:
        from scapy.all import DNS, DNSQR
        if DNS in pkt and pkt[DNS].qd and DNSQR in pkt[DNS]:
            qname = str(pkt[DNS][DNSQR].qname)
            return qname.rstrip(".") if qname else None
    except Exception:
        return None
    return None


def io_bytes(data: bytes) -> "io.BytesIO":
    import io
    return io.BytesIO(data)