import pytest

from app.alerts.manager import AlertManager
from app.schemas.alert import AlertCreate


class _Decision:
    def __init__(self, threat_type: str = "ddos", severity: str = "high",
                 risk_score: float = 0.9, confidence: float = 0.9) -> None:
        self.threat_type = type("Threat", (), {"value": threat_type})()
        self.severity = severity
        self.risk_score = risk_score
        self.confidence = confidence
        self.detection_sources = ["rule"]
        self.score_breakdown = {"total": risk_score}
        self.flow_id = "flow-1"


class _Features:
    def __init__(self, src_ip: str, dst_ip: str = "10.0.10.10") -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = "tcp"
        self.packet_count = 100
        self.byte_count = 1000
        self.syn_ratio = 1.0
        self.unique_dst_ports = 1
        self.connection_frequency = 0.9

    def model_dump(self) -> dict:
        return {"src_ip": self.src_ip, "dst_ip": self.dst_ip, "protocol": self.protocol}


def test_flood_collapses_to_single_target_alert():
    manager = AlertManager()
    fired = 0
    for i in range(20):
        decision = _Decision()
        features = _Features(src_ip=f"1.2.3.{i}")
        evidence = {"features": {"packet_count": 100}}
        if manager.create_alert(decision, features, evidence):
            fired += 1

    assert fired == 1
    recent = manager.recent(10)
    assert len(recent) == 1
    agg = recent[0].alert.evidence["aggregation"]
    assert agg["source_count"] == 20
    assert agg["flow_count"] == 20
    assert agg["packet_count"] == 2000


def test_distinct_targets_emit_distinct_alerts():
    manager = AlertManager()
    for i in range(3):
        decision = _Decision()
        features = _Features(src_ip="1.2.3.4", dst_ip=f"10.0.10.{i}")
        manager.create_alert(decision, features)

    assert len(manager.recent(10)) == 3


def test_aggregation_key_ignores_src_ip():
    from app.alerts.manager import AlertManager as AM
    manager = AM()
    a = _Features("a", dst_ip="10.0.10.1")
    b = _Features("b", dst_ip="10.0.10.1")
    assert a.dst_ip == b.dst_ip
    alert = AlertCreate(
        src_ip="x", dst_ip="10.0.10.1", protocol="tcp", threat_type="ddos",
        severity="high", confidence=0.9, risk_score=0.9,
    )
    assert manager._aggregation_key(alert) == ("10.0.10.1", "tcp", "ddos", "high")