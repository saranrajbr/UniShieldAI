from app.ml.anomaly import AnomalyDetectionEngine
from app.ml.supervised import BaseSupervisedEngine


class ModelRegistry:
    def __init__(self) -> None:
        self._supervised: SupervisedEngineRegistry = SupervisedEngineRegistry()
        self._anomaly: AnomalyEngineRegistry = AnomalyEngineRegistry()

    def register_supervised(self, engine: BaseSupervisedEngine) -> None:
        self._supervised.register(engine)

    def register_anomaly(self, engine: AnomalyDetectionEngine) -> None:
        self._anomaly.register(engine)

    def predict(self, features: dict) -> dict:
        return self._supervised.predict(features)

    def anomaly_score(self, features: dict) -> dict:
        return self._anomaly.score(features)

    @property
    def supervised(self) -> "SupervisedEngineRegistry":
        return self._supervised

    @property
    def anomaly(self) -> "AnomalyEngineRegistry":
        return self._anomaly

    def status(self) -> dict:
        return {
            "supervised_loaded": self._supervised.has_primary_loaded(),
            "anomaly_loaded": self._anomaly.has_primary_loaded(),
        }


class SupervisedEngineRegistry:
    def __init__(self) -> None:
        from app.ml.supervised import SupervisedFallback, SupervisedXGBoostEngine
        self._primary: BaseSupervisedEngine | None = SupervisedXGBoostEngine()
        self._fallback: BaseSupervisedEngine = SupervisedFallback()

    def register(self, engine: BaseSupervisedEngine) -> None:
        self._primary = engine

    def predict(self, features: dict) -> dict:
        if self._primary is not None and getattr(self._primary, "loaded", False):
            return self._primary.predict_proba(features)
        return self._fallback.predict_proba(features)

    def has_primary_loaded(self) -> bool:
        return self._primary is not None and getattr(self._primary, "loaded", False)


class AnomalyEngineRegistry:
    def __init__(self) -> None:
        self._primary: AnomalyDetectionEngine | None = None

    def register(self, engine: AnomalyDetectionEngine) -> None:
        self._primary = engine

    def score(self, features: dict) -> dict:
        if self._primary is not None:
            return self._primary.compute_anomaly_score(features)
        return AnomalyDetectionEngine().compute_anomaly_score(features)

    def has_primary_loaded(self) -> bool:
        return self._primary is not None and self._primary.loaded


model_registry = ModelRegistry()