"""
WebSocket Cyber Range & Generative Security Digital Twin (GSDT) Broker - Version 30.

Streams real-time simulation steps, Merkle-Chain cryptographic verification hashes,
Adversarial Red-Team / Blue-Team scorecard updates, and carrier-scale traffic telemetry
to connected SOC analyst consoles.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.services.cyber_range import SyntheticRangeController, SCENARIO_DEFINITIONS

logger = logging.getLogger(__name__)

router = APIRouter(tags=["V30 Cyber Range WebSocket"])


class CyberRangeWebSocketManager:
    """
    Stateful connection manager for live cyber range simulations,
    streaming telemetry, scorecard ticks, and safe-clone topology states.
    """

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self._redis_client = None

    async def get_redis(self):
        if self._redis_client is None:
            try:
                import redis.asyncio as aioredis
                self._redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            except Exception as e:
                logger.debug(f"Could not connect to Redis for CyberRangeWebSocketManager: {e}")
                self._redis_client = None
        return self._redis_client

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.active_connections:
            self.active_connections[org_id] = []
        self.active_connections[org_id].append(websocket)
        logger.info(f"V30 Cyber Range WebSocket connected for org: {org_id}")
        try:
            await websocket.send_json({
                "type": "CONNECTION_ESTABLISHED",
                "service": "Generative Security Digital Twin (GSDT) & Autonomous Cyber Range",
                "version": "30.0.0",
                "org_id": org_id,
                "status": "Connected to Range Broker",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        except Exception:
            pass

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.active_connections:
            if websocket in self.active_connections[org_id]:
                self.active_connections[org_id].remove(websocket)
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]
        logger.info(f"V30 Cyber Range WebSocket disconnected for org: {org_id}")

    async def broadcast_to_org(self, org_id: str, payload: Dict[str, Any]):
        targets = list(self.active_connections.get(org_id, []))
        if "default-org" in self.active_connections and org_id != "default-org":
            targets.extend(self.active_connections.get("default-org", []))

        for ws in targets:
            try:
                await ws.send_json(payload)
            except Exception as ex:
                logger.debug(f"Failed sending WebSocket message: {ex}")


range_ws_manager = CyberRangeWebSocketManager()


async def execute_scenario_task(controller: SyntheticRangeController, scenario_name: str, org_id: str):
    """
    Executes a multi-step adversarial simulation in the background,
    broadcasting each step over WebSockets with Merkle-chain hashes and scorecard updates.
    """
    steps = SCENARIO_DEFINITIONS.get(scenario_name, SCENARIO_DEFINITIONS.get("APT29_COZYBEAR", []))
    session_id = str(uuid4())

    start_notification = {
        "type": "SIMULATION_SESSION_STARTED",
        "session_id": session_id,
        "scenario_name": scenario_name,
        "org_id": org_id,
        "total_steps": len(steps),
        "status": "RUNNING",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    await range_ws_manager.broadcast_to_org(org_id, start_notification)

    red_score = 0
    blue_score = 0

    for step_data in steps:
        await asyncio.sleep(1.0)
        from app.services.cyber_range import SimulationStep
        step = SimulationStep(
            step_index=step_data["step_index"],
            tactic_id=step_data["tactic_id"],
            technique_id=step_data["technique_id"],
            action_description=step_data["action_description"],
            raw_log_template=step_data["raw_log_template"],
            ocsf_class_uid=step_data.get("ocsf_class_uid", 1007),
            severity_id=step_data.get("severity_id", 3),
            is_detected=step_data.get("is_detected", False),
            remediation_action=step_data.get("remediation_action")
        )

        step_event = await controller.inject_synthetic_telemetry(step, device_id=f"twin-device-{step.step_index}")
        step_event["session_id"] = session_id
        step_event["org_id"] = org_id
        await range_ws_manager.broadcast_to_org(org_id, step_event)

        red_score += 15
        score_update = {
            "type": "SCORE_UPDATE",
            "session_id": session_id,
            "red_score": red_score,
            "blue_score": blue_score,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        await range_ws_manager.broadcast_to_org(org_id, score_update)

        if step.is_detected:
            await asyncio.sleep(0.8)
            blue_score += 25
            containment_event = {
                "type": "CONTAINMENT_TRIGGERED",
                "session_id": session_id,
                "step_index": step.step_index,
                "remediation_action": step.remediation_action,
                "red_score": red_score,
                "blue_score": blue_score,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            await range_ws_manager.broadcast_to_org(org_id, containment_event)

    await asyncio.sleep(0.5)
    complete_notification = {
        "type": "SIMULATION_SESSION_COMPLETED",
        "session_id": session_id,
        "scenario_name": scenario_name,
        "org_id": org_id,
        "final_red_score": red_score,
        "final_blue_score": blue_score,
        "status": "COMPLETED",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    await range_ws_manager.broadcast_to_org(org_id, complete_notification)


async def _handle_range_ws(websocket: WebSocket, org_id: str):
    await range_ws_manager.connect(websocket, org_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": datetime.utcnow().isoformat() + "Z"}))
                continue
            try:
                cmd = json.loads(data)
            except Exception:
                continue

            action = cmd.get("action")
            if action in ("TRIGGER_SCENARIO", "TRIGGER_SIMULATION"):
                scenario_name = cmd.get("scenario") or cmd.get("scenario_name") or "APT29_COZYBEAR"
                controller = SyntheticRangeController(tenant_id=org_id)
                asyncio.create_task(execute_scenario_task(controller, scenario_name, org_id))
            elif action == "BURST_BENCHMARK":
                eps = int(cmd.get("eps", 1000000))
                controller = SyntheticRangeController(tenant_id=org_id)
                result = controller.simulate_carrier_scale_burst(eps_target=eps)
                await websocket.send_json({
                    "type": "BURST_TELEMETRY",
                    "data": result,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
    except WebSocketDisconnect:
        range_ws_manager.disconnect(websocket, org_id)
    except Exception as e:
        logger.debug(f"Cyber range WS closed: {e}")
        range_ws_manager.disconnect(websocket, org_id)


@router.websocket("/api/v30/range/ws")
@router.websocket("/api/v1/range/ws")
async def websocket_v30_range_endpoint_query(websocket: WebSocket, org_id: str = Query("default-org")):
    """WebSocket endpoint establishing V30 Generative Cyber Range stream via query param."""
    await _handle_range_ws(websocket, org_id)


@router.websocket("/api/v30/range/ws/{org_id}")
async def websocket_v30_range_endpoint_path(websocket: WebSocket, org_id: str):
    """WebSocket endpoint establishing V30 Generative Cyber Range stream via path param."""
    await _handle_range_ws(websocket, org_id)

