from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import settings
from app.engine.pipeline import pipeline
from app.ml.model_registry import model_registry
from app.utils.metrics import runtime_metrics

router = APIRouter(prefix="/api/v1/health", tags=["health"])


@router.get("")
async def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "uptime_sec": round(runtime_metrics.uptime_sec(), 1),
        "engine": {
            "rules_loaded": _rule_count(),
            "ml": model_registry.status(),
            "pipeline_queue": pipeline.queue_size,
            "pipeline_active": pipeline._worker is not None and not pipeline._worker.done(),
        },
    }


@router.get("/live")
async def live() -> dict:
    return {"alive": True, "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/ready")
async def ready() -> dict:
    checks = {
        "pipeline_worker": pipeline._worker is not None and not pipeline._worker.done(),
        "rules_loaded": _rule_count() > 0,
    }
    return {"ready": all(checks.values()), "checks": checks}


def _rule_count() -> int:
    try:
        return pipeline.rules.registry.count()
    except Exception:
        return 0