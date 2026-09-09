import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.capture.flow_pcap import flow_pcap_recorder
from app.db.database import init_db
from app.db.persist import persist_metrics_snapshot, persist_worker
from app.engine.pipeline import pipeline
from app.ml.engine import boot_ml_engine
from app.ml.model_registry import model_registry
from app.realtime.manager import connection_manager
from app.realtime.publisher import event_publisher
from app.state.expiry import expiry_manager
from app.utils.metrics import runtime_metrics

from app.api import (
    alerts,
    captures,
    detection,
    health,
    metrics,
    models,
    traffic,
    websocket,
)
from app.realtime.events import AlertEvent

setup_logging()
logger = get_logger("unishield.main")


async def _publish_alert(ctx) -> None:
    try:
        await connection_manager.broadcast(AlertEvent(ctx).payload)
    except Exception:
        logger.exception("Failed to broadcast alert")


async def _wire_publishers() -> None:
    event_publisher.register_stream("metrics", _metrics_producer)
    event_publisher.register_stream("engine_state", _engine_producer)
    pipeline.alert_manager.register_publisher(lambda ctx: _publish_alert(ctx))
    pipeline.alert_manager.register_persister(lambda ctx: persist_worker.submit(ctx))


def _metrics_producer() -> dict:
    return runtime_metrics.snapshot()


def _engine_producer() -> dict:
    return {
        "flows_queued": pipeline.queue_size,
        "active_flows": pipeline.flow_state.size(),
        "alerts_recent": len(pipeline.alert_manager.recent(20)),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)
    await init_db()
    flow_pcap_recorder.start()
    await pipeline.start(workers=settings.pipeline_consumers)
    await persist_worker.start()
    await expiry_manager.start()
    await event_publisher.start()
    await _wire_publishers()

    from app.ingestion.flow_export_listener import flow_export_listener
    await flow_export_listener.start()

    metrics_task = asyncio.create_task(_persist_metrics_loop())

    ml_inference = boot_ml_engine()
    pipeline.ml.inference = ml_inference
    logger.info("ML status: %s", model_registry.status())

    yield
    metrics_task.cancel()
    try:
        await metrics_task
    except asyncio.CancelledError:
        pass

    await flow_export_listener.stop()
    await event_publisher.stop()
    await expiry_manager.stop()
    await persist_worker.stop()
    await pipeline.stop()
    flow_pcap_recorder.stop()
    logger.info("%s stopped", settings.app_name)


async def _persist_metrics_loop() -> None:
    while True:
        await asyncio.sleep(30)
        await persist_metrics_snapshot()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(traffic.router)
app.include_router(alerts.router)
app.include_router(captures.router)
app.include_router(detection.router)
app.include_router(metrics.router)
app.include_router(models.router)
app.include_router(websocket.router)


@app.get("/")
async def root() -> dict:
    return {
        "app": settings.app_name,
        "docs": "/docs",
        "health": "/api/v1/health",
    }


def main() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        access_log=True,
    )


if __name__ == "__main__":
    main()