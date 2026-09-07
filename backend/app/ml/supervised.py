from typing import Protocol

import numpy as np

from app.core.constants import ThreatType


class SupervisedModel(Protocol):
    def predict_proba(self, X) -> dict:
        ...


class BaseSupervisedEngine:
    name = "supervised"

    def predict_proba(self, features: dict) -> dict:
        raise NotImplementedError


class SupervisedFallback(BaseSupervisedEngine):
    def predict_proba(self, features: dict) -> dict:
        syn_ratio = float(features.get("syn_ratio", 0.0))
        conn_freq = float(features.get("connection_frequency", 0.0))
        unique_ports = float(features.get("unique_dst_ports", 0))

        if syn_ratio > 0.8 and conn_freq > 5.0:
            return {
                "threat_type": ThreatType.DOS,
                "probability": 0.85,
                "source": "supervised_fallback",
            }
        if unique_ports > 20:
            return {
                "threat_type": ThreatType.PORT_SCAN,
                "probability": 0.8,
                "source": "supervised_fallback",
            }
        return {
            "threat_type": ThreatType.BENIGN,
            "probability": 0.5,
            "source": "supervised_fallback",
        }


class SupervisedXGBoostEngine(BaseSupervisedEngine):
    name = "supervised_xgboost"

    def __init__(self, model=None, preprocessor=None, class_names: list[str] | None = None) -> None:
        self.model = model
        self.preprocessor = preprocessor
        self.class_names = class_names or [c.value for c in ThreatType]

    @property
    def loaded(self) -> bool:
        return self.model is not None

    def predict_proba(self, features: dict) -> dict:
        if self.model is None:
            return SupervisedFallback().predict_proba(features)

        try:
            import xgboost as xgb

            vector = self.preprocessor.transform(features) if self.preprocessor else None
            if vector is None:
                vector = list(features.values())
            dmatrix = xgb.DMatrix([vector])
            class_probs = self.model.predict(dmatrix)
            probs = class_probs[0]
            if isinstance(probs, np.ndarray) and probs.ndim >= 1:
                prob_list = list(probs)
                predicted_idx = prob_list.index(max(prob_list))
                probability = float(prob_list[predicted_idx])
            else:
                predicted_idx = 1 if float(probs) >= 0.5 else 0
                probability = float(probs)
            predicted_idx = min(predicted_idx, len(self.class_names) - 1)
            return {
                "threat_type": self.class_names[predicted_idx],
                "probability": round(max(0.0, min(1.0, probability)), 4),
                "source": self.name,
            }
        except Exception:
            return SupervisedFallback().predict_proba(features)


class SupervisedEngineManager:
    def __init__(self) -> None:
        self._engines: list[BaseSupervisedEngine] = [
            SupervisedXGBoostEngine(),
            SupervisedFallback(),
        ]

    def register(self, engine: BaseSupervisedEngine) -> None:
        self._engines.insert(0, engine)

    def predict(self, features: dict) -> dict:
        for engine in self._engines:
            if getattr(engine, "loaded", True):
                return engine.predict_proba(features)
        return self._engines[-1].predict_proba(features)

    def engines(self) -> list[BaseSupervisedEngine]:
        return self._engines