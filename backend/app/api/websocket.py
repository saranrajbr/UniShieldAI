from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.logging import get_logger
from app.realtime.manager import connection_manager

logger = get_logger("unishield.api.websocket")

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await connection_manager.connect(websocket)
    logger.info("WebSocket client connected (total=%d)", connection_manager.active_count)
    try:
        await websocket.send_json({
            "type": "hello",
            "data": {"message": "UniShield AI realtime feed active"},
        })
        while True:
            message = await websocket.receive_text()
            if message.strip().lower() in {"ping", ""}:
                await websocket.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        await connection_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected (total=%d)", connection_manager.active_count)
    except Exception:
        await connection_manager.disconnect(websocket)


@router.websocket("/ws/alerts")
async def alerts_endpoint(websocket: WebSocket) -> None:
    await connection_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await connection_manager.disconnect(websocket)