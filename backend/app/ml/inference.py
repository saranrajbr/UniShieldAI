from app.core.constants import ThreatType
from app.core.logging import get_logger
from app.ml.model_registry import ModelRegistry

logger = get_logger("unishield.ml")


class MLInferenceEngine:
    def __init__(self, registry: ModelRegistry | None = None) -> None:
        self.registry = registry or ModelRegistry()
        self._inference_count = 0
        self._errors = 0

    def run(self, features: dict) -> dict:
        try:
            supervised = self.registry.predict(features)
            anomaly = self.registry.anomaly_score(features)
            self._inference_count += 1
        except Exception:
            self._errors += 1
            logger.exception("ML inference failed")
            return {
                "supervised": {"probability": 0.0, "threat_type": ThreatType.BENIGN},
                "anomaly": {"anomaly_score": 0.0, "is_anomaly": False},
            }

        probability = float(supervised.get("probability", 0.0))
        supervised_threat = supervised.get("threat_type", ThreatType.BENIGN.value)
        anomaly_score = float(anomaly.get("anomaly_score", 0.0))
        is_anomaly = bool(anomaly.get("is_anomaly", False))

        # Trust the supervised classifier when it is confident. The isolation-
        # forest raw decision threshold is noisy, so only blend the anomaly
        # signal (shifting toward it) while the supervised model is uncertain.
        confidence = abs(probability - 0.5) * 2.0
        if confidence >= 0.6:
            blended = probability
        else:
            anomaly_gain = anomaly_score - 0.5
            if is_anomaly and anomaly_gain > 0:
                blended = min(1.0, probability + 0.15 * anomaly_gain)
            else:
                blended = probability

        return {
            "supervised": supervised,
            "anomaly": anomaly,
            "blended_ml_score": round(min(1.0, blended), 4),
            "is_anomaly": is_anomaly,
            "inference_count": self._inference_count,
        }

    def stats(self) -> dict:
        return {"inferences": self._inference_count, "errors": self._errors}