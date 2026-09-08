from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import ThreatType


class RuleResult(BaseModel):
    source: str
    matched: bool = False
    score: float = 0.0
    details: dict = Field(default_factory=dict)


class MLResult(BaseModel):
    source: str
    probability: float = 0.0
    anomaly_score: float = 0.0
    predicted_class: Optional[ThreatType] = None
    details: dict = Field(default_factory=dict)


class DecisionResult(BaseModel):
    flow_id: str
    risk_score: float = 0.0
    confidence: float = 0.0
    threat_type: ThreatType = ThreatType.BENIGN
    severity: str = "info"
    is_threat: bool = False
    detection_sources: list[str] = Field(default_factory=list)
    score_breakdown: dict = Field(default_factory=dict)


class DetectionRequest(BaseModel):
    flow_id: str
    run_at: datetime = Field(default_factory=datetime.utcnow)


class DetectionResponse(BaseModel):
    decision: DecisionResult
