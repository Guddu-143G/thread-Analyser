# app/api/ws_provenance_stream.py
import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Dict, List, Any
import redis.asyncio as aioredis
from app.core.config import settings

logger = logging.getLogger("ws_provenance_stream")
router = APIRouter(prefix="/api/v1/provenance", tags=["Provenance Graph Stream"])


class ProvenanceWebSocketManager:
    """
    Manages stateful WebSocket connections for streaming real-time Data Provenance Graph (DPG) 
    nodes and edges directly to active analyst consoles, organized by tenant org_id.
    """
    def __init__(self):
        # org_id -> active web socket channels
        self.connections: Dict[str, List[WebSocket]] = {}
        self.redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379/0")

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.connections:
            self.connections[org_id] = []
        self.connections[org_id].append(websocket)
        # Send initial confirmation
        try:
            await websocket.send_json({
                "type": "CONNECTION_ESTABLISHED",
                "service": "V26 Data Provenance Stream",
                "org_id": org_id
            })
        except Exception:
            pass

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.connections:
            if websocket in self.connections[org_id]:
                self.connections[org_id].remove(websocket)
            if not self.connections[org_id]:
                del self.connections[org_id]

    async def run_provenance_broadcast_loop(self, websocket: WebSocket, org_id: str):
        """
        Listens for client pings while maintaining the channel open for outbound event pushes.
        """
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            self.disconnect(websocket, org_id)
        except Exception:
            self.disconnect(websocket, org_id)


manager = ProvenanceWebSocketManager()


@router.websocket("/ws")
async def provenance_websocket_endpoint(websocket: WebSocket, org_id: str = Query("default_org")):
    """
    WebSocket router establishing live communication channels for real-time 
    data provenance mapping and SOAR lifecycle execution monitoring.
    """
    await manager.connect(websocket, org_id)
    await manager.run_provenance_broadcast_loop(websocket, org_id)
