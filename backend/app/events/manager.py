from datetime import datetime, timezone
import json
import logging
from typing import Any
from fastapi import WebSocket

from app.core.redis import publish_pipeline_event, set_ephemeral_state

logger = logging.getLogger("gateway.events")


class ConnectionManager:
    """
    Manages active WebSocket connections grouped by dataset_id.
    """

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}
        self.global_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket, dataset_id: str | None = None):
        await websocket.accept()
        if dataset_id:
            if dataset_id not in self.active_connections:
                self.active_connections[dataset_id] = []
            self.active_connections[dataset_id].append(websocket)
        else:
            self.global_connections.append(websocket)

    def disconnect(self, websocket: WebSocket, dataset_id: str | None = None):
        if dataset_id and dataset_id in self.active_connections:
            if websocket in self.active_connections[dataset_id]:
                self.active_connections[dataset_id].remove(websocket)
            if not self.active_connections[dataset_id]:
                del self.active_connections[dataset_id]
        elif websocket in self.global_connections:
            self.global_connections.remove(websocket)

    async def broadcast_to_dataset(self, dataset_id: str, event_data: dict[str, Any]):
        message_str = json.dumps(event_data)

        # Broadcast to specific dataset listeners
        if dataset_id in self.active_connections:
            to_remove = []
            for connection in self.active_connections[dataset_id]:
                try:
                    await connection.send_text(message_str)
                except Exception:
                    to_remove.append(connection)
            for dead in to_remove:
                self.disconnect(dead, dataset_id)

        # Also broadcast to global listeners
        to_remove_global = []
        for connection in self.global_connections:
            try:
                await connection.send_text(message_str)
            except Exception:
                to_remove_global.append(connection)
        for dead in to_remove_global:
            self.disconnect(dead)


event_manager = ConnectionManager()


async def emit_pipeline_event(
    event_type: str,
    dataset_id: str,
    version: int,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Constructs and broadcasts a real-time event.
    Stores ephemeral state in Redis and publishes to WebSocket clients.
    """
    payload: dict[str, Any] = {
        "event": event_type,
        "dataset_id": dataset_id,
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }

    # Ephemeral state in Redis
    state_key = f"pipeline:{dataset_id}:{version}"
    await set_ephemeral_state(state_key, payload)

    # Publish to Redis channel for multi-worker support
    await publish_pipeline_event(f"events:{dataset_id}", payload)

    # Broadcast to locally connected WebSocket clients
    await event_manager.broadcast_to_dataset(dataset_id, payload)

    return payload
