from app.core.constants import ThreatType


class RiskFusion:
    def __init__(self, weights: dict[str, float]) -> None:
        self.weights = weights

    def fuse(self, rule_scores: dict[str, float], ml_scores: dict[str, float]) -> dict:
        risk = 0.0
        weight_total = 0.0

        for source, score in rule_scores.items():
            weight = self.weights.get(source, 0.0)
            risk += float(score) * weight
            weight_total += weight

        supervised = ml_scores.get("blended_ml_score", 0.0)
        risk += supervised * self.weights.get("ml_blended", 0.0)
        weight_total += self.weights.get("ml_blended", 0.0)

        denominator = weight_total if weight_total > 0 else 1.0
        return {
            "risk_score": round(min(1.0, risk / denominator), 4),
            "weighted_sum": round(risk, 4),
            "weight_normalized": round(denominator, 4),
            "breakdown": {
                **{k: round(float(v), 4) for k, v in rule_scores.items()},
                "ml_blended": round(float(supervised), 4),
            },
        }


DEFAULT_WEIGHTS: dict[str, float] = {
    "signature": 0.30,
    "statistical": 0.25,
    "behavioral": 0.25,
    "ml_blended": 0.20,
}

risk_fusion = RiskFusion(DEFAULT_WEIGHTS)