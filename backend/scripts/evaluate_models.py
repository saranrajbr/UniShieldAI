"""Evaluate trained ML models on a held-out synthetic dataset."""

import argparse
import logging
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("eval")


def evaluate(args) -> None:
    from app.ml.preprocessing import Preprocessor
    from scripts.train_models import build_synthetic_dataset

    X, y = build_synthetic_dataset(args.samples, seed=args.seed)
    preprocessor = Preprocessor().fit(X)

    X_scaled = np.asarray(
        [preprocessor.transform(row.tolist()) for row in X], dtype=np.float64
    )

    model_path = Path(args.model_path)
    if not model_path.exists():
        logger.error("Model not found: %s", model_path)
        return

    from xgboost import XGBClassifier

    model = XGBClassifier()
    model.load_model(str(model_path))
    predictions = model.predict(X_scaled)

    logger.info("Accuracy: %.4f", accuracy_score(y, predictions))
    logger.info("\n%s", classification_report(y, predictions, target_names=["benign", "threat"]))
    logger.info("Confusion matrix:\n%s", confusion_matrix(y, predictions))

    precision, recall, f1, _ = precision_recall_fscore_support(y, predictions, average="binary")
    logger.info("Precision=%.3f Recall=%.3f F1=%.3f", precision, recall, f1)
    from sklearn.metrics import roc_auc_score

    try:
        proba = model.predict_proba(X_scaled)[:, 1]
        logger.info("AUC=%.4f", roc_auc_score(y, proba))
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate UniShield AI models")
    parser.add_argument("--model-path", default="models/xgboost/model.json")
    parser.add_argument("--samples", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    evaluate(args)


if __name__ == "__main__":
    main()