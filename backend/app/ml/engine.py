"""ML engine high-level entrypoint.

Loads the model registry, wires the supervised + anomaly engines, and exposes
a single `evaluate(features)` interface for the pipeline.
"""

from typing import Any

from app.ml.inference import MLInferenceEngine
from app.ml.model_loader import model_loader
from app.ml.model_registry import model_registry


def boot_ml_engine() -> MLInferenceEngine:
    engine = MLInferenceEngine(registry=model_registry)
    xgboost = model_loader.load_xgboost()
    if xgboost is not None:
        model_registry.register_supervised(xgboost)
    isolation_forest = model_loader.load_isolation_forest()
    if isolation_forest is not None:
        model_registry.register_anomaly(isolation_forest)
    return engine


class MLEngine:
    def __init__(self, inference: MLInferenceEngine | None = None) -> None:
        self.inference = inference or MLInferenceEngine()

    def evaluate(self, features: dict) -> dict[str, Any]:
        return self.inference.run(features)

    def status(self) -> dict:
        return {"registry": model_registry.status(), "stats": self.inference.stats()}


ml_engine = MLEngine()