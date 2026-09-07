import math


class ConfidenceEstimator:
    def __init__(self) -> None:
        self.source_weights = {
            "signature": 0.30,
            "statistical": 0.20,
            "behavioral": 0.20,
            "ml_blended": 0.30,
        }

    def estimate(self, score_breakdown: dict, rule_count: int,
                 is_anomaly: bool, detection_source_count: int) -> float:
        if not score_breakdown:
            return 0.0

        evidence_strength = 0.0
        for source, score in score_breakdown.items():
            evidence_strength += float(score) * self.source_weights.get(source, 0.1)

        multiplicity = min(1.0, detection_source_count / 3.0)
        rule_weight = min(1.0, rule_count / 4.0)
        anomaly_weight = 1.0 if is_anomaly else 0.0

        confidence = (
            evidence_strength * 0.6
            + multiplicity * 0.2
            + rule_weight * 0.1
            + anomaly_weight * 0.1
        )
        return round(min(1.0, max(0.0, confidence)), 4)


confidence_estimator = ConfidenceEstimator()