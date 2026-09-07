import json
from pathlib import Path

import numpy as np

from app.core.config import settings
from app.ml.feature_schema import FeatureSchema


class MissingModelError(FileNotFoundError):
    pass


class PreprocessingError(Exception):
    pass


class Preprocessor:
    def __init__(self, scaler=None, feature_schema: FeatureSchema | None = None) -> None:
        self.scaler = scaler
        self.feature_schema = feature_schema or FeatureSchema()
        self._mean = None
        self._std = None

    def fit(self, X: np.ndarray) -> "Preprocessor":
        X = np.asarray(X, dtype=np.float64)
        self._mean = np.mean(X, axis=0)
        self._std = np.std(X, axis=0)
        self._std[self._std == 0] = 1.0
        return self

    def transform(self, features: dict | list[float]) -> list[float]:
        vector = self.vectorize(features)
        if self.scaler is not None:
            scaled = self.scaler.transform(np.asarray([vector], dtype=np.float64))
            return scaled[0].tolist()
        if self._mean is not None and self._std is not None:
            vector = np.asarray(vector, dtype=np.float64)
            return ((vector - self._mean) / self._std).tolist()
        return vector

    def vectorize(self, features: dict | list[float]) -> list[float]:
        if isinstance(features, dict):
            return self.feature_schema.vectorize(features)
        return list(features)

    def save(self, path: str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "mean": self._mean.tolist() if self._mean is not None else None,
            "std": self._std.tolist() if self._std is not None else None,
            "schema": self.feature_schema.to_json(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "Preprocessor":
        path = Path(path)
        if not path.exists():
            raise MissingModelError(f"Preprocessor not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        preprocessor = cls(feature_schema=FeatureSchema.from_json(data.get("schema", {})))
        preprocessor._mean = np.asarray(data["mean"], dtype=np.float64) if data.get("mean") else None
        preprocessor._std = np.asarray(data["std"], dtype=np.float64) if data.get("std") else None
        return preprocessor


preprocessor = Preprocessor()