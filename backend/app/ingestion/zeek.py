import csv
import io
from datetime import datetime

from app.ingestion.base import FlowParserBase
from app.schemas.traffic import FlowRecord


class ZeekParser(FlowParserBase):
    format_name = "zeek"

    FIELD_MAP = {
        "proto": "protocol",
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dst_ip",
        "id.resp_p": "dst_port",
        "orig_pkts": "packet_count",
        "orig_bytes": "src_bytes",
        "resp_pkts": "proto_packets",
        "resp_bytes": "dst_bytes",
        "duration": "duration",
    }

    def __init__(self) -> None:
        self._fields: list[str] = []
        self._reader: csv.DictReader | None = None
        self._current_lines: list[str] = []

    def _ensure_fields(self, header: str) -> None:
        header = header.strip().lstrip("#").strip()
        self._fields = [f.strip() for f in csv.reader([header]).__next__() if f.strip()]

    def parse_line(self, line: str) -> FlowRecord | None:
        line = line.strip()
        if not line or line.startswith("##"):
            return None
        if line.startswith("#separator"):
            return None
        if line.startswith("#fields"):
            self._ensure_fields(line)
            return None
        if line.startswith("#"):
            return None
        if not self._fields:
            return None

        parts = next(csv.reader([line], delimiter="\t"))
        if len(parts) != len(self._fields):
            parts += [""] * (len(self._fields) - len(parts))
        row = dict(zip(self._fields, parts))
        return self._build_flow(row)

    def _build_flow(self, row: dict) -> FlowRecord | None:
        try:
            ts = datetime.fromisoformat(row.get("ts", "")) if row.get("ts") else datetime.utcnow()
        except ValueError:
            ts = datetime.utcnow()

        protocol = (row.get("proto") or row.get("conn_state") or "tcp").lower()
        src_ip = row.get("id.orig_h", "0.0.0.0")
        dst_ip = row.get("id.resp_h", "0.0.0.0")
        src_port = _int_or_none(row.get("id.orig_p"))
        dst_port = _int_or_none(row.get("id.resp_p"))

        packet_count = _int_or_zero(row.get("orig_pkts")) + _int_or_zero(row.get("resp_pkts"))
        byte_count = _int_or_zero(row.get("orig_bytes")) + _int_or_zero(row.get("resp_bytes"))

        return FlowRecord(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=byte_count,
        )

    def parse_payload(self, payload: bytes) -> list[FlowRecord]:
        text = payload.decode("utf-8", errors="ignore")
        records: list[FlowRecord] = []
        for line in text.splitlines():
            record = self.parse_line(line)
            if record is not None:
                records.append(record)
        return records

    def parse_file(self, path: str) -> list[FlowRecord]:
        records: list[FlowRecord] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                record = self.parse_line(line)
                if record is not None:
                    records.append(record)
        return records


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_or_zero(value: str) -> int:
    return _int_or_none(value) or 0