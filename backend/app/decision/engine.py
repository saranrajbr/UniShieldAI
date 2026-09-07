from app.core.config import settings
from app.decision.classifier import ThreatClassifier, classifier
from app.decision.confidence import ConfidenceEstimator, confidence_estimator
from app.decision.risk_fusion import RiskFusion, risk_fusion
from app.decision.severity import SeverityClassifier, severity_classifier
from app.schemas.detection import DecisionResult


class DecisionEngine:
    def __init__(
        self,
        fusion: RiskFusion = risk_fusion,
        classifier_: ThreatClassifier = classifier,
        confidence_: ConfidenceEstimator = confidence_estimator,
        severity_: SeverityClassifier = severity_classifier,
    ) -> None:
        self.fusion = fusion
        self.classifier = classifier_
        self.confidence = confidence_
        self.severity = severity_

    def decide(self, flow_id: str, rule_assessment: dict,
               ml_assessment: dict) -> DecisionResult:
        rule_scores: dict[str, float] = rule_assessment.get("source_scores", {})
        rule_matches = rule_assessment.get("matches", [])

        fused = self.fusion.fuse(
            rule_scores=rule_scores,
            ml_scores={
                "blended_ml_score": ml_assessment.get("blended_ml_score", 0.0),
            },
        )

        anomaly = ml_assessment.get("anomaly", {})
        anomaly_score = float(anomaly.get("anomaly_score", 0.0))
        is_anomaly = bool(anomaly.get("is_anomaly", False))

        risk_score = float(fused["risk_score"])
        threat_type = self.classifier.classify(
            risk_score, rule_matches, ml_assessment, anomaly_score
        )

        detection_sources = self._detection_sources(rule_scores, ml_assessment, is_anomaly)
        confidence = self.confidence.estimate(
            fused.get("breakdown", {}),
            rule_count=len(rule_matches),
            is_anomaly=is_anomaly,
            detection_source_count=len(detection_sources),
        )
        severity = self.severity.classify(risk_score, confidence)

        return DecisionResult(
            flow_id=flow_id,
            risk_score=round(risk_score, 4),
            confidence=confidence,
            threat_type=threat_type,
            severity=self.severity.label(severity),
            is_threat=risk_score >= settings.detection_threshold and threat_type != "benign",
            detection_sources=detection_sources,
            score_breakdown=fused.get("breakdown", {}),
        )

    @staticmethod
    def _detection_sources(rule_scores: dict, ml_assessment: dict, is_anomaly: bool) -> list[str]:
        sources: list[str] = []
        for source in ("signature", "statistical", "behavioral"):
            if rule_scores.get(source, 0.0) > 0:
                sources.append(source)
        if ml_assessment.get("supervised", {}).get("probability", 0.0) > 0.5:
            sources.append("supervised_ml")
        if is_anomaly:
            sources.append("anomaly_detection")
        return sources


decision_engine = DecisionEngine()