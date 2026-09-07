from fastapi import APIRouter

from app.features.statistics import snapshot as feature_statistics_snapshot
from app.engine.pipeline import pipeline
from app.utils.metrics import runtime_metrics

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])


@router.get("")
async def metrics() -> dict:
    return runtime_metrics.snapshot()


@router.get("/traffic")
async def traffic_metrics() -> dict:
    return feature_statistics_snapshot()


@router.get("/engine")
async def engine_metrics() -> dict:
    from app.ingestion.flow_export_listener import flow_export_listener
    return {
        "flows_queued": pipeline.queue_size,
        "active_flows": pipeline.flow_state.size(),
        "alerts_recent": len(pipeline.alert_manager.recent()),
        "alert_stats": pipeline.alert_manager.stats(),
        "ml_stats": pipeline.ml.inference.stats(),
        "rules": {r["rule_id"]: r["match_count"] for r in pipeline.rules.registry.stats()},
        "flow_export": flow_export_listener.stats(),
    }