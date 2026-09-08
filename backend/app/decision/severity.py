from app.core.constants import Severity


class SeverityClassifier:
    def classify(self, risk_score: float, confidence: float) -> Severity:
        effective = risk_score * (0.7 + 0.3 * confidence)
        if effective >= 0.95:
            return Severity.CRITICAL
        if effective >= 0.8:
            return Severity.HIGH
        if effective >= 0.6:
            return Severity.MEDIUM
        if effective >= 0.4:
            return Severity.LOW
        return Severity.INFO

    def label(self, severity: Severity) -> str:
        return severity.name.lower()


severity_classifier = SeverityClassifier()