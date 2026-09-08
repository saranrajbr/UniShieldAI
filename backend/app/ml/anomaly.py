import math


class AnomalyDetectionEngine:
    name = "isolation_forest"

    def __init__(self, model=None, preprocessor=None) -> None:
        self.model = model
        self.preprocessor = preprocessor

    @property
    def loaded(self) -> bool:
        return self.model is not None

    def compute_anomaly_score(self, features: dict) -> dict:
        if self.model is not None:
            try:
                vector = self.preprocessor.transform(features) if self.preprocessor else list(features.values())
                prediction = self.model.predict([vector])[0]
                raw_score = float(self.model.decision_function([vector])[0])
                anomaly_score = _sigmoid(-raw_score)
                return {
                    "anomaly_score": round(anomaly_score, 4),
                    "is_anomaly": bool(prediction == -1),
                }
            except Exception:
                pass

        heuristic = self._heuristic_score(features)
        return {
            "anomaly_score": heuristic,
            "is_anomaly": heuristic > 0.5,
        }

    @staticmethod
    def _heuristic_score(features: dict) -> float:
        syn_ratio = float(features.get("syn_ratio", 0.0))
        conn_freq = float(features.get("connection_frequency", 0.0))
        unique_ports = float(features.get("unique_dst_ports", 0))
        packets = float(features.get("packets_per_sec", 0))
        bytes_per_sec = float(features.get("bytes_per_sec", 0))

        deviation = 0.0
        deviation += syn_ratio * 0.25
        deviation += min(1.0, conn_freq / 100.0) * 0.25
        deviation += min(1.0, unique_ports / 50.0) * 0.2
        deviation += min(1.0, packets / 2000.0) * 0.15
        deviation += min(1.0, bytes_per_sec / 2_000_000.0) * 0.15
        return min(1.0, deviation)


def _sigmoid(value: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-value))
    except OverflowError:
        return 1.0 if value > 0 else 0.0