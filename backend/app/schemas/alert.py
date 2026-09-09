from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AlertCreate(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    protocol: str
    threat_type: str
    severity: str
    confidence: float
    risk_score: float
    evidence: dict = Field(default_factory=dict)
    detection_sources: list[str] = Field(default_factory=list)
    flow_ids: list[str] = Field(default_factory=list)


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    threat_type: str
    severity: str
    confidence: float
    risk_score: float
    evidence: dict
    detection_sources: list[str]
    status: str = "open"
    pcap_path: str | None = None
    aggregation: dict = Field(default_factory=dict)


class AlertList(BaseModel):
    total: int
    alerts: list[AlertOut] = Field(default_factory=list)
