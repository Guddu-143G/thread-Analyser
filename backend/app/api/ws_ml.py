import json
import asyncio
import logging
from typing import Dict, List, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.detection.anomaly_pipeline import ml_manager
from app.tasks.ml_training import generate_synthetic_telemetry_batch

logger = logging.getLogger("ws_ml_stream")
router = APIRouter(tags=["ML Anomaly Stream"])


class MLTelemetryWebSocketManager:
    """
    Manages bidirectional WebSocket streams for real-time telemetry anomaly scoring
    and live PCA boundary projections per organization tenant.
    """
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.connections:
            self.connections[org_id] = []
        self.connections[org_id].append(websocket)
        try:
            await websocket.send_json({
                "type": "CONNECTION_ESTABLISHED",
                "service": "V27 ML Anomaly Engine Live Telemetry Stream",
                "org_id": org_id,
                "version": "v27.0"
            })
        except Exception:
            pass

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.connections:
            if websocket in self.connections[org_id]:
                self.connections[org_id].remove(websocket)
            if not self.connections[org_id]:
                del self.connections[org_id]

    async def broadcast_evaluation(self, org_id: str, payload: Dict[str, Any]):
        if org_id in self.connections:
            for ws in list(self.connections[org_id]):
                try:
                    await ws.send_json(payload)
                except Exception:
                    self.disconnect(ws, org_id)

    async def handle_stream(self, websocket: WebSocket, org_id: str):
        simulation_task = None
        try:
            while True:
                msg_text = await websocket.receive_text()
                if msg_text == "ping":
                    await websocket.send_text("pong")
                    continue

                try:
                    data = json.loads(msg_text)
                except Exception:
                    continue

                msg_type = data.get("type", "EVALUATE")
                if msg_type == "EVALUATE":
                    event = data.get("event", {})
                    eval_res = ml_manager.evaluate_telemetry(org_id, event)
                    await websocket.send_json({
                        "type": "EVALUATION_RESULT",
                        "raw_event": event,
                        "evaluation": eval_res
                    })
                elif msg_type == "START_SIMULATION":
                    # Generate and stream 5 rapid synthetic evaluation events
                    batch = generate_synthetic_telemetry_batch(count=5)
                    for evt in batch:
                        eval_res = ml_manager.evaluate_telemetry(org_id, evt)
                        await websocket.send_json({
                            "type": "SIMULATION_TICK",
                            "raw_event": evt,
                            "evaluation": eval_res
                        })
                        await asyncio.sleep(0.3)
        except WebSocketDisconnect:
            self.disconnect(websocket, org_id)
        except Exception as e:
            logger.debug(f"WebSocket closed for org {org_id}: {e}")
            self.disconnect(websocket, org_id)


manager = MLTelemetryWebSocketManager()


@router.websocket("/api/v1/stream/ml-telemetry")
@router.websocket("/api/v27/live-telemetry")
async def ml_telemetry_stream(websocket: WebSocket, org_id: str = Query("default_org")):
    """Live WebSocket streaming endpoint for ML Anomaly scoring."""
    await manager.connect(websocket, org_id)
    await manager.handle_stream(websocket, org_id)
