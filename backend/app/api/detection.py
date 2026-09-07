from fastapi import APIRouter

from app.core.logging import get_logger
from app.engine.pipeline import pipeline
from app.schemas.detection import DetectionRequest, DetectionResponse

logger = get_logger("unishield.api.detection")

router = APIRouter(prefix="/api/v1/detection", tags=["detection"])


@router.get("/engines")
async def engines() -> dict:
    return {
        "rules": {
            "loaded": pipeline.rules.registry.count(),
            "categories": _rule_categories(),
        },
        "ml": pipeline.ml.status(),
        "decision": {
            "threshold": None,
            "is_threat_gt": 0.6,
        },
    }


@router.post("/analyze", response_model=DetectionResponse)
async def analyze(request: DetectionRequest) -> DetectionResponse:
    features = pipeline.extractor.last_features()
    if features is None or features.flow_id != request.flow_id:
        return DetectionResponse(
            decision=_empty_decision(request.flow_id)
        )

    rule_assessment = pipeline.rules.result_assessment(features.model_dump())
    ml_assessment = pipeline.ml.inference.run(features.model_dump())
    decision = pipeline.decision.decide(request.flow_id, rule_assessment, ml_assessment)
    return DetectionResponse(decision=decision)


def _rule_categories() -> dict[str, int]:
    by_category: dict[str, int] = {}
    for rule in pipeline.rules.registry.all():
        by_category[rule.category] = by_category.get(rule.category, 0) + 1
    return by_category


def _empty_decision(flow_id: str):
    from app.core.constants import ThreatType
    from app.schemas.detection import DecisionResult
    return DecisionResult(
        flow_id=flow_id,
        risk_score=0.0,
        confidence=0.0,
        threat_type=ThreatType.BENIGN,
        severity="info",
        is_threat=False,
    )