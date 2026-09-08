from app.core.constants import ThreatType
from app.rules.base import BaseRule, RuleMatch


class BehavioralRule(BaseRule):
    category = "behavioral"

    def __init__(self, detect: callable, rule_id: str, rule_name: str,
                 weight: float = 1.0, threat_type: ThreatType = ThreatType.SUSPICIOUS_TRAFFIC,
                 severity: int = 2) -> None:
        super().__init__(weight=weight)
        self.detect = detect
        self.rule_id = rule_id
        self.rule_name = rule_name
        self._threat_type = threat_type
        self._severity = severity

    def evaluate(self, features: dict) -> RuleMatch | None:
        result = self.detect(features)
        if not result:
            return None
        if isinstance(result, dict):
            score = float(result.get("score", 0.5))
            details = dict(result)
            details.pop("score", None)
        else:
            score = float(result)
            details = {}
        return self._match(score, self._threat_type, self._severity, **details)


def default_behavioral_rules() -> list[BehavioralRule]:
    return [
        BehavioralRule(
            _periodic_pattern_rule,
            "behav_periodic_conn",
            "Periodic connection pattern (tunneling/beaconing)",
            threat_type=ThreatType.C2_COMMUNICATION, severity=3,
        ),
        BehavioralRule(
            _syn_flood_pattern_rule,
            "behav_syn_flood",
            "SYN flood signature (half-open ratio)",
            threat_type=ThreatType.DDoS, severity=4,
        ),
        BehavioralRule(
            _port_sweep_rule,
            "behav_port_sweep",
            "Sequential port sweep",
            threat_type=ThreatType.PORT_SCAN, severity=3,
        ),
        BehavioralRule(
            _small_pkts_many_conn_rule,
            "behav_small_pkt_many_conn",
            "Small packets across many connections",
            threat_type=ThreatType.RECONNAISSANCE, severity=2,
        ),
        BehavioralRule(
            _brute_force_rule,
            "behav_brute_force",
            "Repeated auth attempts (brute force)",
            threat_type=ThreatType.BRUTE_FORCE, severity=4,
        ),
        BehavioralRule(
            _lateral_beacon_rule,
            "behav_lateral_move",
            "Lateral movement pattern",
            threat_type=ThreatType.LATERAL_MOVEMENT, severity=3,
        ),
        BehavioralRule(
            _tls_ja3_blocklist_rule,
            "behav_tls_ja3_blocklist",
            "TLS client fingerprint in known-malicious JA3 set (no decryption)",
            threat_type=ThreatType.MALWARE_COMMUNICATION, severity=4,
        ),
    ]


def _periodic_pattern_rule(features: dict) -> dict | None:
    periodicity = features.get("periodicity", 0.0)
    if periodicity > 0.7:
        return {"score": min(1.0, 0.4 + periodicity / 2), "periodicity": round(periodicity, 3)}
    return None


def _syn_flood_pattern_rule(features: dict) -> dict | None:
    syn_ratio = features.get("syn_ratio", 0.0)
    if syn_ratio > 0.9:
        return {"score": 0.9, "syn_ratio": round(syn_ratio, 3)}
    return None


def _port_sweep_rule(features: dict) -> dict | None:
    unique_ports = features.get("unique_dst_ports", 0)
    connection_frequency = features.get("connection_frequency", 0.0)
    if unique_ports >= 10:
        return {"score": 0.75, "unique_dst_ports": unique_ports}
    if unique_ports >= 5 and connection_frequency >= 1.0:
        return {"score": 0.5, "unique_dst_ports": unique_ports}
    return None


def _brute_force_rule(features: dict) -> dict | None:
    unique_ports = features.get("unique_dst_ports", 0)
    connection_frequency = features.get("connection_frequency", 0.0)
    dst_port = features.get("dst_port")
    auth_ports = {22, 23, 3389, 445, 5985, 5900}
    if dst_port in auth_ports and unique_ports == 1 and connection_frequency >= 1.0:
        return {"score": 0.8, "connection_frequency": round(connection_frequency, 3)}
    return None


def _small_pkts_many_conn_rule(features: dict) -> dict | None:
    small_ratio = features.get("small_packet_ratio", 0.0)
    unique_ips = features.get("unique_dst_ips", 0)
    if small_ratio > 0.6 and unique_ips >= 5:
        return {"score": 0.65, "small_packet_ratio": round(small_ratio, 3)}
    return None


def _lateral_beacon_rule(features: dict) -> dict | None:
    outbound_ratio = features.get("outbound_inbound_ratio", 0.5)
    connection_frequency = features.get("connection_frequency", 0.0)
    if 0.0 < outbound_ratio < 0.3 and connection_frequency > 2.0:
        return {"score": 0.6, "outbound_inbound_ratio": round(outbound_ratio, 3)}
    return None


def _tls_ja3_blocklist_rule(features: dict) -> dict | None:
    ja3 = features.get("tls_ja3")
    if not ja3:
        return None
    from app.core.constants import KNOWN_MALICIOUS_JA3
    if ja3 in KNOWN_MALICIOUS_JA3:
        return {"score": 0.95, "ja3_fingerprint": ja3, "source": "JA3 blocklist"}
    return None