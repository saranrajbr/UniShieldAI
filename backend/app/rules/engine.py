from app.rules.base import BaseRule, RuleMatch
from app.rules.registry import RuleEngine, RuleRegistry

__all__ = ["BaseRule", "RuleMatch", "RuleEngine", "RuleRegistry"]


def build_engine(load_defaults: bool = True, signature_path: str | None = None) -> RuleEngine:
    registry = RuleRegistry()
    if load_defaults:
        registry.load_defaults()
    if signature_path:
        registry.load_signature_file(signature_path)
    return RuleEngine(registry=registry)