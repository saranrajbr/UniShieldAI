import json
from datetime import datetime

from app.ingestion.base import FlowParserBase
from app.schemas.traffic import FlowRecord


class FlowParser(FlowParserBase):
    format_name = "unishield-flow-json"

    def parse_line(self, line: str) -> FlowRecord | None:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        return self._build(data)

    def parse_payload(self, payload: bytes) -> list[FlowRecord]:
        try:
            data = json.loads(payload.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [self._build(item) for item in data if self._build(item) is not None]
        if isinstance(data, dict):
            flows = data.get("flows", [data])
            return [self._build(f) for f in flows if self._build(f) is not None]
        return []

    def _build(self, data: dict) -> FlowRecord | None:
        try:
            ts_value = data.get("ts") or data.get("timestamp")
            ts = datetime.fromisoformat(ts_value) if isinstance(ts_value, str) else datetime.utcnow()
        except (ValueError, TypeError):
            ts = datetime.utcnow()

        packet_count = int(data.get("packet_count", data.get("packets", 0)))
        byte_count = int(data.get("byte_count", data.get("bytes", 0)))

        return FlowRecord(
            ts=ts,
            src_ip=str(data.get("src_ip", data.get("id.orig_h", "0.0.0.0"))),
            dst_ip=str(data.get("dst_ip", data.get("id.resp_h", "0.0.0.0"))),
            src_port=_int_or_none(data.get("src_port", data.get("id.orig_p"))),
            dst_port=_int_or_none(data.get("dst_port", data.get("id.resp_p"))),
            protocol=str(data.get("protocol", data.get("proto", "tcp"))).lower(),
            direction=str(data.get("direction", "unknown")),
            packet_count=packet_count,
            byte_count=byte_count,
        )


def _int_or_none(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None