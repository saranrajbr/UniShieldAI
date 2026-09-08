from fastapi import APIRouter

from app.core.config import settings
from app.db.database import SessionLocal
from app.ml.model_registry import model_registry
from app.rules.engine import build_engine
from app.rules.registry import RuleRegistry

router = APIRouter(prefix="/api/v1/models", tags=["models"])


@router.get("")
async def list_models() -> dict:
    return {
        "status": model_registry.status(),
        "paths": {
            "xgboost": settings.xgboost_model_path,
            "isolation_forest": settings.isolation_forest_model_path,
            "scaler": settings.scaler_path,
        },
    }


@router.post("/reload")
async def reload_models() -> dict:
    try:
        from app.ml.model_loader import model_loader

        xgboost = model_loader.load_xgboost()
        if xgboost is not None:
            model_registry.register_supervised(xgboost)
        isolation_forest = model_loader.load_isolation_forest()
        if isolation_forest is not None:
            model_registry.register_anomaly(isolation_forest)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "status": model_registry.status()}


@router.get("/rules")
async def list_rules() -> dict:
    engine = build_engine(load_defaults=True)
    return {"count": engine.registry.count(), "rules": engine.registry.stats()}