from app.core.constants import ThreatType

THREAT_PRIORITY: dict[ThreatType, int] = {
    ThreatType.BENIGN: 0,
    ThreatType.RECONNAISSANCE: 1,
    ThreatType.SUSPICIOUS_TRAFFIC: 2,
    ThreatType.PORT_SCAN: 2,
    ThreatType.BRUTE_FORCE: 3,
    ThreatType.LATERAL_MOVEMENT: 3,
    ThreatType.C2_COMMUNICATION: 4,
    ThreatType.DATA_EXFILTRATION: 4,
    ThreatType.MALWARE_COMMUNICATION: 4,
    ThreatType.DOS: 4,
    ThreatType.DDoS: 4,
    ThreatType.DNS_TUNNELING: 5,  # more specific technique than generic exfil
}


class ThreatClassifier:
    def classify(self, risk_score: float, rule_matches: list,
                 ml_result: dict, anomaly_score: float) -> ThreatType:
        rule_candidates: list[tuple[float, ThreatType]] = [
            (match.score, match.threat_type) for match in rule_matches
        ]

        # Specific rule matches (port_scan, brute_force, c2, ...) always
        # out-rank the generic ML/anomaly "threat" label: the supervised model
        # is binary and can only contribute a broad suspicious_traffic signal,
        # which would otherwise win by raw score and drown out real TTPs.
        specific = [
            (score, tt)
            for score, tt in rule_candidates
            if tt != ThreatType.SUSPICIOUS_TRAFFIC
        ]
        if specific:
            winner_score, winner = max(
                specific, key=lambda item: (item[0], self.priority(item[1]))
            )
            # DNS tunneling is a technique-level subset of data exfiltration.
            # When a high-entropy DNS channel is detected, that label is strictly
            # more actionable than the generic byte-ratio exfil that co-fires.
            if winner in (ThreatType.DATA_EXFILTRATION, ThreatType.MALWARE_COMMUNICATION):
                for score, tt in specific:
                    if tt == ThreatType.DNS_TUNNELING:
                        return tt
            return winner

        candidates: list[tuple[float, ThreatType]] = list(rule_candidates)

        supervised_threat = ml_result.get("supervised", {}).get(
            "threat_type", ThreatType.BENIGN.value
        )
        probability = float(ml_result.get("supervised", {}).get("probability", 0.0))
        try:
            candidates.append((probability, ThreatType(supervised_threat)))
        except ValueError:
            # Binary model labels are "benign"/"threat" — keep a generic hit as
            # suspicious_traffic just like anomaly, but it never masks rules.
            if probability >= 0.5 and supervised_threat != ThreatType.BENIGN.value:
                candidates.append((probability, ThreatType.SUSPICIOUS_TRAFFIC))

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