import json
import logging
import pickle
from pathlib import Path

from app.core.config import settings
from app.ml.anomaly import AnomalyDetectionEngine
from app.ml.preprocessing import MissingModelError, Preprocessor
from app.ml.supervised import SupervisedXGBoostEngine

logger = logging.getLogger("unishield.model_loader")


class ModelLoader:
    def load_preprocessor(self, path: str | None = None) -> Preprocessor:
        path = path or settings.scaler_path
        try:
            return Preprocessor.load(path)
        except MissingModelError:
            return Preprocessor()

    def load_xgboost(self, path: str | None = None) -> SupervisedXGBoostEngine | None:
        path = Path(path or settings.xgboost_model_path)
        if not path.exists():
            logger.warning("XGBoost model not found at %s — using fallback", path)
            return None
        try:
            import xgboost as xgb

            model = xgb.Booster()
            model.load_model(str(path))
            return SupervisedXGBoostEngine(
                model=model,
                preprocessor=self.load_preprocessor(),
                class_names=self._load_class_names(),
            )
        except ImportError:
            logger.warning("xgboost not installed — using fallback")
            return None
        except Exception:
            logger.exception("Failed to load XGBoost model")
            return None

    def load_isolation_forest(self, path: str | None = None) -> AnomalyDetectionEngine | None:
        path = Path(path or settings.isolation_forest_model_path)
        if not path.exists():
            logger.warning("Isolation Forest model not found at %s — using heuristic", path)
            return None
        try:
            with path.open("rb") as fh:
                model = pickle.load(fh)
            return AnomalyDetectionEngine(
                model=model,
                preprocessor=self.load_preprocessor(),
            )
        except Exception:
            logger.exception("Failed to load Isolation Forest model")
            return None

    @staticmethod
    def _load_class_names() -> list[str]:
        path = Path(settings.feature_columns_path).parent.parent / "class_names.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        from app.core.constants import ThreatType
        return list(ThreatType)


model_loader = ModelLoader()