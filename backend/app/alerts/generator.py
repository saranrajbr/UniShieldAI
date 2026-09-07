import time

from app.schemas.alert import AlertCreate
from app.utils.hashing import alert_fingerprint, short_id


class AlertGenerator:
    def __init__(self) -> None:
        self._counter = 0

    def generate(self, decision, flow_features, evidence: dict | None = None) -> AlertCreate:
        self._counter += 1
        alert_id = f"AL-{int(time.time() * 1000):x}-{self._counter:04d}"

        evidence = evidence or {}
        evidence.setdefault("features", _feature_summary(flow_features))
        evidence.setdefault("score_breakdown", decision.score_breakdown)

        return AlertCreate(
            src_ip=flow_features.src_ip,
            dst_ip=flow_features.dst_ip,
            protocol=flow_features.protocol,
            threat_type=decision.threat_type.value if hasattr(decision.threat_type, "value") else str(decision.threat_type),
            severity=decision.severity,
            confidence=decision.confidence,
            risk_score=decision.risk_score,
            evidence=evidence,
            detection_sources=decision.detection_sources,
            flow_ids=[decision.flow_id],
        )

    def fingerprint(self, alert: AlertCreate) -> str:
        return alert_fingerprint({
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "protocol": alert.protocol,
            "threat_type": alert.threat_type,
            "severity": alert.severity,
        })


def _feature_summary(features) -> dict:
    if features is None:
        return {}
    return {
        "packet_count": getattr(features, "packet_count", 0),
        "byte_count": getattr(features, "byte_count", 0),
        "syn_ratio": round(getattr(features, "syn_ratio", 0.0), 4),
        "unique_dst_ports": getattr(features, "unique_dst_ports", 0),
        "connection_frequency": round(getattr(features, "connection_frequency", 0.0), 4),
    }