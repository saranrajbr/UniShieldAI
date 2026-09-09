from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class EventBase:
    event_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertEvent(EventBase):
    def __init__(self, alert) -> None:
        super().__init__(
            event_type="alert",
            payload={
                "alert_id": alert.alert_id,
                "timestamp": alert.alert.timestamp.isoformat(),
                "src_ip": alert.alert.src_ip,
                "dst_ip": alert.alert.dst_ip,
                "protocol": alert.alert.protocol,
                "threat_type": alert.alert.threat_type,
                "severity": alert.alert.severity,
                "confidence": alert.alert.confidence,
                "risk_score": alert.alert.risk_score,
                "detection_sources": alert.alert.detection_sources,
                "evidence": alert.alert.evidence,
                "pcap_path": alert.pcap_path,
                "aggregation": alert.alert.evidence.get("aggregation", {}),
            },
        )


@dataclass
class DetectionEvent(EventBase):
    def __init__(self, decision) -> None:
        super().__init__(
            event_type="detection",
            payload={
                "flow_id": decision.flow_id,
                "risk_score": decision.risk_score,
                "confidence": decision.confidence,
                "threat_type": decision.threat_type.value if hasattr(decision.threat_type, "value") else str(decision.threat_type),
                "severity": decision.severity,
                "is_threat": decision.is_threat,
                "detection_sources": decision.detection_sources,
            },
        )


@dataclass
class MetricsEvent(EventBase):
    def __init__(self, metrics: dict) -> None:
        super().__init__(event_type="metrics", payload=metrics)


@dataclass
class ConnectionEvent(EventBase):
    def __init__(self, direction: str, src_ip: str, dst_ip: str) -> None:
        super().__init__(
            event_type="connection",
            payload={"direction": direction, "src_ip": src_ip, "dst_ip": dst_ip},
        )


@dataclass
class SystemEvent(EventBase):
    def __init__(self, level: str, message: str, **extra: Any) -> None:
        super().__init__(
            event_type="system",
            payload={"level": level, "message": message, **extra},
        )