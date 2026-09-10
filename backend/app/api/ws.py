import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.events.manager import event_manager

logger = logging.getLogger("gateway.api.ws")
router = APIRouter(tags=["realtime"])


@router.websocket("/ws/{dataset_id}")
async def websocket_dataset_endpoint(websocket: WebSocket, dataset_id: str):
    """
    Real-time WebSocket connection for streaming pipeline execution events
    for a specific dataset.
    """
    await event_manager.connect(websocket, dataset_id)
    try:
        # Keep connection open and handle client pings
        while True:
            data = await websocket.receive_text()
            # Respond to client ping
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        event_manager.disconnect(websocket, dataset_id)
    except Exception as exc:
        logger.warning(f"WebSocket error for dataset {dataset_id}: {exc}")
        event_manager.disconnect(websocket, dataset_id)


@router.websocket("/ws")
async def websocket_global_endpoint(websocket: WebSocket):
    """
    Global WebSocket connection for streaming all dataset gateway events.
    """
    await event_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        event_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"Global WebSocket error: {exc}")
        event_manager.disconnect(websocket)
