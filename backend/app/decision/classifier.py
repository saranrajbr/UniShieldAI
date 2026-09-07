from app.core.constants import ThreatType

THREAT_PRIORITY: dict[ThreatType, int] = {
    ThreatType.BENIGN: 0,
    ThreatType.RECONNAISSANCE: 1,
    ThreatType.SUSPICIOUS_TRAFFIC: 2,
    ThreatType.PORT_SCAN: 2,
    ThreatType.BRUTE_FORCE: 3,
    ThreatType.LATERAL_MOVEMENT: 3,
    ThreatType.DNS_TUNNELING: 3,
    ThreatType.C2_COMMUNICATION: 4,
    ThreatType.DATA_EXFILTRATION: 4,
    ThreatType.MALWARE_COMMUNICATION: 4,
    ThreatType.DOS: 4,
    ThreatType.DDoS: 4,
}


class ThreatClassifier:
    def classify(self, risk_score: float, rule_matches: list,
                 ml_result: dict, anomaly_score: float) -> ThreatType:
        candidates: list[tuple[float, ThreatType]] = []

        for match in rule_matches:
            candidates.append((match.score, match.threat_type))

        supervised_threat = ml_result.get("supervised", {}).get(
            "threat_type", ThreatType.BENIGN.value
        )
        probability = float(ml_result.get("supervised", {}).get("probability", 0.0))
        try:
            candidates.append((probability, ThreatType(supervised_threat)))
        except ValueError:
            pass

        if anomaly_score > 0.6:
            candidates.append((anomaly_score, ThreatType.SUSPICIOUS_TRAFFIC))

        if risk_score < 0.4:
            return ThreatType.BENIGN
        if not candidates:
            return ThreatType.SUSPICIOUS_TRAFFIC

        strongest_score, strongest_threat = max(candidates, key=lambda item: item[0])
        return strongest_threat

    def priority(self, threat: ThreatType) -> int:
        return THREAT_PRIORITY.get(threat, 2)


classifier = ThreatClassifier()