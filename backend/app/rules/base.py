import abc
import time
from dataclasses import dataclass, field

from app.core.constants import ThreatType


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    category: str
    score: float = 0.0
    threat_type: ThreatType = ThreatType.SUSPICIOUS_TRAFFIC
    severity: int = 1
    details: dict = field(default_factory=dict)


class BaseRule(abc.ABC):
    rule_id: str = ""
    rule_name: str = ""
    category: str = "generic"
    description: str = ""

    def __init__(self, weight: float = 1.0) -> None:
        self.weight = weight
        self.match_count = 0
        self.last_match_ts: float | None = None

    @abc.abstractmethod
    def evaluate(self, features: dict) -> RuleMatch | None:
        raise NotImplementedError

    def _match(self, score: float, threat_type: ThreatType = ThreatType.SUSPICIOUS_TRAFFIC,
               severity: int = 1, **details) -> RuleMatch:
        self.match_count += 1
        self.last_match_ts = time.time()
        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            category=self.category,
            score=max(0.0, min(1.0, score * self.weight)),
            threat_type=threat_type,
            severity=severity,
            details=details,
        )

    def stats(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "match_count": self.match_count,
            "last_match_ts": self.last_match_ts,
        }