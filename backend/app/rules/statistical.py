from typing import Any

from app.core.constants import ThreatType
from app.rules.base import BaseRule, RuleMatch
from app.rules.thresholds import STATISTICAL_THRESHOLDS


class StatisticalRule(BaseRule):
    category = "statistical"

    def __init__(self, field: str, threshold: float, operator: str = "gte",
                 weight: float = 1.0, rule_id: str | None = None,
                 rule_name: str | None = None,
                 threat_type: ThreatType = ThreatType.SUSPICIOUS_TRAFFIC,
                 severity: int = 2) -> None:
        super().__init__(weight=weight)
        self.field = field
        self.threshold = threshold
        self.operator = operator
        self.rule_id = rule_id or f"stat_{field}_{operator}_{threshold}"
        self.rule_name = rule_name or f"Statistical: {field} {operator} {threshold}"
        self._threat_type = threat_type
        self._severity = severity

    def evaluate(self, features: dict) -> RuleMatch | None:
        if self.field not in features:
            return None
        actual = features.get(self.field)
        try:
            severity = self._score(actual)
        except (TypeError, ValueError):
            return None
        if severity > 0:
            return self._match(severity, self._threat_type, self._severity,
                               field=self.field, actual=float(actual),
                               threshold=self.threshold, operator=self.operator)
        return None

    def _score(self, actual: Any) -> float:
        try:
            actual = float(actual)
        except (TypeError, ValueError):
            return 0.0
        if self.operator == "gte":
            return min(1.0, 0.5 + (actual - self.threshold) / max(1e-9, self.threshold))
        if self.operator == "lte":
            if actual <= self.threshold:
                return min(1.0, 0.5 + (self.threshold - actual) / max(1e-9, self.threshold))
        if self.operator == "gt":
            if actual > self.threshold:
                return min(1.0, 0.4 + (actual - self.threshold) / max(1e-9, self.threshold))
        if self.operator == "lt":
            if actual < self.threshold:
                return min(1.0, 0.4 + (self.threshold - actual) / max(1e-9, self.threshold))
        return 0.0


def default_statistical_rules() -> list[StatisticalRule]:
    return [
        StatisticalRule(
            field="syn_ratio", threshold=STATISTICAL_THRESHOLDS["syn_ratio"]["high"],
            operator="gte", rule_id="stat_syn_ratio_high",
            rule_name="High SYN ratio", threat_type=ThreatType.DOS, severity=3,
        ),
        StatisticalRule(
            field="connection_frequency", threshold=STATISTICAL_THRESHOLDS["connection_frequency"]["high"],
            operator="gte", rule_id="stat_conn_freq_high",
            rule_name="Abnormal connection frequency", threat_type=ThreatType.LATERAL_MOVEMENT, severity=3,
        ),
        StatisticalRule(
            field="packets_per_sec", threshold=STATISTICAL_THRESHOLDS["packets_per_sec"]["high"],
            operator="gte", rule_id="stat_pps_high",
            rule_name="Packet rate above baseline", threat_type=ThreatType.DOS, severity=2,
        ),
        StatisticalRule(
            field="bytes_per_sec", threshold=STATISTICAL_THRESHOLDS["bytes_per_sec"]["high"],
            operator="gte", rule_id="stat_bps_high",
            rule_name="Byte rate above baseline", threat_type=ThreatType.DATA_EXFILTRATION, severity=3,
        ),
        StatisticalRule(
            field="dns_entropy", threshold=STATISTICAL_THRESHOLDS["dns_entropy"]["high"],
            operator="gte", rule_id="stat_dns_entropy_high",
            rule_name="High DNS entropy", threat_type=ThreatType.DNS_TUNNELING, severity=3,
        ),
        StatisticalRule(
            field="unique_dst_ports", threshold=STATISTICAL_THRESHOLDS["unique_dst_ports"]["high"],
            operator="gte", rule_id="stat_unique_ports_high",
            rule_name="Many distinct destination ports", threat_type=ThreatType.PORT_SCAN, severity=3,
        ),
        StatisticalRule(
            field="unique_dst_ips", threshold=STATISTICAL_THRESHOLDS["unique_dst_ips"]["high"],
            operator="gte", rule_id="stat_unique_ips_high",
            rule_name="Many distinct destination hosts", threat_type=ThreatType.LATERAL_MOVEMENT, severity=3,
        ),
        StatisticalRule(
            field="outbound_inbound_ratio", threshold=STATISTICAL_THRESHOLDS["outbound_inbound_ratio"]["high"],
            operator="gte", rule_id="stat_outbound_ratio_high",
            rule_name="Dominant outbound traffic", threat_type=ThreatType.DATA_EXFILTRATION, severity=2,
        ),
        StatisticalRule(
            field="small_packet_ratio", threshold=STATISTICAL_THRESHOLDS["small_packet_ratio"]["high"],
            operator="gte", rule_id="stat_small_packet_high",
            rule_name="Many small packets", threat_type=ThreatType.RECONNAISSANCE, severity=2,
        ),
        StatisticalRule(
            field="source_entropy", threshold=STATISTICAL_THRESHOLDS["source_entropy"]["high"],
            operator="gte", rule_id="stat_source_entropy_high",
            rule_name="Widespread source-IP spread (spoofed/reflection flood)",
            threat_type=ThreatType.DDoS, severity=4,
        ),
        StatisticalRule(
            field="udp_amp_ratio", threshold=STATISTICAL_THRESHOLDS["udp_amp_ratio"]["high"],
            operator="gte", rule_id="stat_udp_amp_high",
            rule_name="UDP amplification signature (large amp payloads)",
            threat_type=ThreatType.DDoS, severity=4,
        ),
    ]