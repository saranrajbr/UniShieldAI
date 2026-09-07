from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    ts: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    direction: str = "unknown"
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    dns_query: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_ja3s: Optional[str] = None


class FlowBatchIn(BaseModel):
    sensor_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    flows: list[FlowRecord] = Field(default_factory=list)


class FlowIngestResponse(BaseModel):
    received: int
    accepted: int
    rejected: int
    flow_ids: list[str] = Field(default_factory=list)
