"""Router flow-export ingesters: NetFlow v5, NetFlow v9 / IPFIX (v10) and sFlow v5.

The PS input surface is "exported flow records (NetFlow/IPFIX/sFlow) from the
router on the unidirectional link". These parsers turn raw UDP datagrams on the
monitor port into the same `FlowRecord` objects used by every other ingestion
path, so detection engine, rules and ML treat a router export identically to a
sensor batch.

NetFlow v9 / IPFIX are template-based: the parser caches the templates an
exporter sends inside a datagram and decodes subsequent data sets from them.
"""

import struct
from datetime import datetime, timezone
from typing import Optional

from app.core.logging import get_logger
from app.schemas.traffic import FlowRecord

logger = get_logger("unishield.ingest.netflow")

DEFAULT_PCAP_BATCH_CAP = 1000

_PROTOCOL_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}

# IPFIX / NetFlow v9 field types used to map a record to a FlowRecord.
_FIELD_SRC4 = 12
_FIELD_DST4 = 15
_FIELD_SRC6 = 13
_FIELD_DST6 = 16
_FIELD_SRCPORT = 11
_FIELD_DSTPORT = 14
_FIELD_PROTO = 7
_FIELD_PACKETS = 2  # packetDeltaCount
_FIELD_OCTETS = 1  # octetDeltaCount
_FIELD_TCPSPECIAL = 136  # tcpControlBits (sfxed)


def parse_flow_export(data: bytes) -> list[FlowRecord]:
    """Dispatch a raw UDP flow-export datagram to the matching parser."""
    if len(data) < 4:
        return []
    first16 = struct.unpack(">HH", data[:4])
    version = first16[0]
    try:
        if version == 5:
            return NetFlowV5Parser().parse(data)
        if version == 9:
            return NetFlowV9Parser().parse(data)
        if version == 10:
            return IPFIXParser().parse(data)
    except Exception:
        logger.exception("flow exporter parse failed for version %s", version)
    # sFlow v4/v5 use a full 32-bit version scalar.
    sflow_version = struct.unpack(">I", data[:4])[0]
    if sflow_version in (4, 5):
        return SFlowParser().parse(data)
    logger.warning("Unsupported flow-export version header: %s", version)
    return []


def _ip(addr: bytes) -> str:
    if len(addr) == 4:
        return ".".join(str(b) for b in addr)
    if len(addr) == 16:
        return ":".join(f"{int.from_bytes(addr[i:i+2], 'big'):x}" for i in range(0, 16, 2))
    return ""


def _protocol_name(value: int | None) -> str:
    return _PROTOCOL_PROTO.get(value or 0, str(value) if value is not None else "unknown")


class PersistentFlowExportDecoder:
    """Stateful decoder that keeps NetFlow v9 / IPFIX template caches across
    datagrams, as exporters commonly send templates in a separate datagram."""

    def __init__(self) -> None:
        self._v9 = NetFlowV9Parser()
        self._ipfix = IPFIXParser()

    def decode(self, data: bytes) -> list[FlowRecord]:
        if len(data) < 4:
            return []
        version = struct.unpack(">HH", data[:4])[0]
        if version == 9:
            return self._v9.parse(data)
        if version == 10:
            return self._ipfix.parse(data)
        return parse_flow_export(data)


class NetFlowV5Parser:
    """NetFlow v5: fixed 24-byte header + N 48-byte records."""

    def parse(self, data: bytes) -> list[FlowRecord]:
        if len(data) < 24:
            return []
        _, count = struct.unpack(">HH", data[0:4])
        unix_secs, unix_nsecs = struct.unpack(">II", data[8:16])
        base_ts = datetime.fromtimestamp(unix_secs + unix_nsecs / 1e9, tz=timezone.utc)
        records: list[FlowRecord] = []
        idx = 24
        for _ in range(min(count, DEFAULT_PCAP_BATCH_CAP)):
            rec = data[idx : idx + 48]
            if len(rec) < 48:
                break
            idx += 48
            src, dst = struct.unpack(">4s4s", rec[0:8])
            d_pkts, d_octets = struct.unpack(">II", rec[16:24])
            first, last = struct.unpack(">II", rec[24:32])
            src_port, dst_port = struct.unpack(">HH", rec[32:36])
            tcp_flags = rec[37]
            proto = rec[38]
            start = base_ts if first == 0 and last == 0 else (
                datetime.fromtimestamp(
                    unix_secs - (last // 1000 if last != 0 else 0),
                    tz=timezone.utc,
                )
            )
            _ = start  # kept for ts provenance; record ts uses export base time
            records.append(
                FlowRecord(
                    ts=base_ts if last == 0 else datetime.fromtimestamp(
                        unix_secs - (last // 1000), tz=timezone.utc
                    ),
                    src_ip=_ip(src),
                    dst_ip=_ip(dst),
                    src_port=src_port or None,
                    dst_port=dst_port or None,
                    protocol=_protocol_name(proto),
                    packet_count=d_pkts,
                    byte_count=d_octets,
                    syn_count=int((tcp_flags & 0x02) > 0) if proto == 6 else 0,
                    ack_count=int((tcp_flags & 0x10) > 0) if proto == 6 else 0,
                    rst_count=int((tcp_flags & 0x04) > 0) if proto == 6 else 0,
                    fin_count=int((tcp_flags & 0x01) > 0) if proto == 6 else 0,
                )
            )
        return records


class _TemplateBasedParser:
    """Shared template cache + decoding for NetFlow v9 and IPFIX (v10)."""

    def __init__(self) -> None:
        self._templates: dict[int, list[tuple[int, int]]] = {}
        self.version = 0

    def is_v9(self) -> bool:
        return self.version == 9

    def _header_len(self) -> int:
        return 20 if self.version == 9 else 16

    def _parse_header(self, data: bytes) -> tuple[int, datetime]:
        if self.version == 9:
            _, _count = struct.unpack(">HH", data[0:4])
            unix_secs = struct.unpack(">I", data[8:12])[0]
            return _count, datetime.fromtimestamp(unix_secs, tz=timezone.utc)
        _length = struct.unpack(">H", data[2:4])[0]
        export_time = struct.unpack(">I", data[4:8])[0]
        return _length, datetime.fromtimestamp(export_time, tz=timezone.utc)

    def _decode_data_record(self, fields: list[tuple[int, int]], body: bytes) -> dict:
        out: dict[str, object] = {}
        off = 0
        for ftype, flen in fields:
            if off + flen > len(body):
                break
            raw = body[off : off + flen]
            off += flen
            if ftype == _FIELD_SRC4:
                out["src_ip"] = _ip(raw[-4:])
            elif ftype == _FIELD_SRC6:
                out["src_ip"] = _ip(raw[-16:])
            elif ftype == _FIELD_DST4:
                out["dst_ip"] = _ip(raw[-4:])
            elif ftype == _FIELD_DST6:
                out["dst_ip"] = _ip(raw[-16:])
            elif ftype == _FIELD_SRCPORT:
                out["src_port"] = int.from_bytes(raw[-2:], "big")
            elif ftype == _FIELD_DSTPORT:
                out["dst_port"] = int.from_bytes(raw[-2:], "big")
            elif ftype == _FIELD_PROTO:
                out["protocol"] = _protocol_name(raw[-1])
            elif ftype == _FIELD_PACKETS:
                out["packet_count"] = int.from_bytes(raw[-4:], "big")
            elif ftype == _FIELD_OCTETS:
                out["byte_count"] = int.from_bytes(raw[-4:], "big")
        return out


class NetFlowV9Parser(_TemplateBasedParser):
    def __init__(self) -> None:
        super().__init__()
        self.version = 9

    def parse(self, data: bytes) -> list[FlowRecord]:
        if len(data) < self._header_len():
            return []
        _count, base_ts = self._parse_header(data)
        idx = self._header_len()
        records: list[FlowRecord] = []
        while idx + 4 <= len(data):
            set_id, set_len = struct.unpack(">HH", data[idx : idx + 4])
            idx += 4
            if set_len < 4 or idx + set_len - 4 > len(data):
                break
            body = data[idx : idx + set_len - 4]
            idx += set_len - 4
            if set_id < 256:  # template set
                self._load_template_set(body)
                continue
            self._decode_data_set(set_id, body, base_ts, records)
        return records

    def _load_template_set(self, body: bytes) -> None:
        off = 0
        while off + 4 <= len(body):
            tid, field_count = struct.unpack(">HH", body[off : off + 4])
            off += 4
            fields: list[tuple[int, int]] = []
            for _ in range(field_count):
                if off + 4 > len(body):
                    break
                ftype, flen = struct.unpack(">HH", body[off : off + 4])
                off += 4
                fields.append((ftype, flen))
            self._templates[tid] = fields

    def _decode_data_set(self, tid: int, body: bytes, base_ts, records: list[FlowRecord]) -> None:
        fields = self._templates.get(tid)
        if not fields:
            return
        rec_len = sum(f for _, f in fields)
        if rec_len <= 0:
            return
        off = 0
        while off + rec_len <= len(body):
            decoded = self._decode_data_record(fields, body[off : off + rec_len])
            off += rec_len
            if decoded.get("src_ip") and decoded.get("dst_ip"):
                records.append(self._record_from(decoded, base_ts))

    @staticmethod
    def _record_from(d: dict, ts: datetime) -> FlowRecord:
        return FlowRecord(
            ts=ts,
            src_ip=str(d["src_ip"]),
            dst_ip=str(d["dst_ip"]),
            src_port=d.get("src_port"),
            dst_port=d.get("dst_port"),
            protocol=str(d.get("protocol", "unknown")),
            packet_count=int(d.get("packet_count", 0)),
            byte_count=int(d.get("byte_count", 0)),
        )


class IPFIXParser(NetFlowV9Parser):
    def __init__(self) -> None:
        super().__init__()
        self.version = 10


class SFlowParser:
    """sFlow v5: parses datagram header + flow samples / flow records."""

    def parse(self, data: bytes) -> list[FlowRecord]:
        if len(data) < 24:
            return []
        version = struct.unpack(">I", data[0:4])[0]
        if version not in (4, 5):
            return []
        num_samples = struct.unpack(">I", data[20:24])[0]
        idx = 24
        records: list[FlowRecord] = []
        for _ in range(num_samples):
            if idx + 8 > len(data):
                break
            sample_type, sample_len = struct.unpack(">II", data[idx : idx + 8])
            idx += 8
            if idx + sample_len > len(data):
                break
            body = data[idx : idx + sample_len]
            idx += sample_len
            if sample_type == 1:
                self._parse_flow_sample(body, records)
        return records

    def _parse_flow_sample(self, body: bytes, records: list[FlowRecord]) -> None:
        if len(body) < 32:
            return
        sampling_rate = struct.unpack(">I", body[8:12])[0]
        num_records = struct.unpack(">I", body[28:32])[0]
        scale = sampling_rate if sampling_rate and sampling_rate > 1 else 1
        idx = 32
        for _ in range(num_records):
            if idx + 8 > len(body):
                return
            fmt, rlen = struct.unpack(">II", body[idx : idx + 8])
            idx += 8
            if idx + rlen > len(body):
                return
            rdata = body[idx : idx + rlen]
            idx += rlen
            if fmt == 3:  # extended_socket4: 16 bytes
                # src_ip(4) dst_ip(4) src_port(2) dst_port(2)
                # tcp_flags(1) protocol(1) tos(1) padding(1)
                if len(rdata) < 14:
                    continue
                proto = rdata[13]
                rec = FlowRecord(
                    src_ip=_ip(rdata[0:4]),
                    dst_ip=_ip(rdata[4:8]),
                    src_port=struct.unpack(">H", rdata[8:10])[0] or None,
                    dst_port=struct.unpack(">H", rdata[10:12])[0] or None,
                    protocol=_protocol_name(proto),
                    packet_count=scale,
                    byte_count=len(rdata) * scale,
                    ts=datetime.now(timezone.utc),
                )
                if proto == 6:
                    flags = rdata[12]
                    rec.syn_count = int((flags & 0x02) > 0)
                    rec.ack_count = int((flags & 0x10) > 0)
                    rec.rst_count = int((flags & 0x04) > 0)
                    rec.fin_count = int((flags & 0x01) > 0)
                records.append(rec)
            elif fmt == 4:  # extended_router ipv4
                # next_hop(4) src_mask(4) dst_mask(4) src_ip(4) dst_ip(4)
                if len(rdata) < 20:
                    continue
                records.append(
                    FlowRecord(
                        src_ip=_ip(rdata[12:16]),
                        dst_ip=_ip(rdata[16:20]),
                        packet_count=scale,
                        byte_count=len(rdata) * scale,
                        ts=datetime.now(timezone.utc),
                    )
                )
            elif fmt in (1001, 1002):  # ingress/egress counter samples
                # if_index(4) if_type(4) if_speed(4) if_direction(4) if_status(4)
                # if_in_octets(8) if_in_packets(8) if_in_errors(4) if_in_drops(4)
                if len(rdata) < 44:
                    continue
                records.append(
                    FlowRecord(
                        src_ip="0.0.0.0",
                        dst_ip="0.0.0.0",
                        protocol="unknown",
                        packet_count=int.from_bytes(rdata[24:32], "big"),
                        byte_count=int.from_bytes(rdata[16:24], "big"),
                        ts=datetime.now(timezone.utc),
                    )
                )