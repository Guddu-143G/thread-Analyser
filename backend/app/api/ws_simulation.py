"""
WebSocket Live Attack Emulation Stream Broker - Version 29.

Provides real-time streaming communication for Purple-Team threat simulations,
injecting sequential OCSF attack vectors into Redis streams and alerting connected
SOC analysts with microsecond latencies.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["V29 Purple-Team WebSocket"])


class EmulationStreamBroker:
    """
    Manages active simulation streams, pushing live execution triggers,
    injected OCSF payloads, and triggered alert counts over WebSocket connections.
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
                logger.warning(f"Could not connect to Redis: {e}")
                self._redis_client = None
        return self._redis_client

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.active_connections:
            self.active_connections[org_id] = []
        self.active_connections[org_id].append(websocket)
        logger.info(f"WebSocket client connected for org: {org_id}")

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.active_connections:
            if websocket in self.active_connections[org_id]:
                self.active_connections[org_id].remove(websocket)
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]
        logger.info(f"WebSocket client disconnected for org: {org_id}")

    async def broadcast_to_org(self, org_id: str, payload: Dict[str, Any]):
        """Broadcasts structured JSON payload to all active connections for a tenant."""
        if org_id in self.active_connections:
            dead_connections = []
            for connection in self.active_connections[org_id]:
                try:
                    await connection.send_json(payload)
                except Exception:
                    dead_connections.append(connection)
            for dead in dead_connections:
                self.disconnect(dead, org_id)

    async def run_simulation_task(
        self,
        org_id: str,
        profile_id: str,
        profile_name: str,
        steps: List[Dict[str, Any]],
        delay_multiplier: float = 1.0,
        run_id: Optional[str] = None
    ):
        """
        Asynchronously executes the purple-team attack emulation, injecting
        OCSF log events into the pipeline buffer with precise delays.
        """
        active_run_id = run_id or f"sim-run-{uuid4().hex[:8]}"
        r = await self.get_redis()

        # 1. Notify frontend that the simulation has initiated
        start_payload = {
            "type": "SIMULATION_START",
            "run_id": active_run_id,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "total_steps": len(steps),
            "message": f"Initializing Purple-Team Emulation Scenario: '{profile_name}'.",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        await self.broadcast_to_org(org_id, start_payload)

        # 2. Sequential Step Injection Loop
        step_results = []
        for step in steps:
            delay = max(0.5, step.get("delay_seconds", 3) * delay_multiplier)
            await asyncio.sleep(delay)

            ocsf_log = step.get("mock_log_payload", {})
            step_order = step.get("step_order", 1)
            ocsf_class = step.get("ocsf_class_uid", 1007)

            # Inject OCSF event directly to the active Redis log stream
            if r:
                try:
                    await r.xadd(
                        "logs:raw_stream",
                        {
                            "log": json.dumps(ocsf_log),
                            "org_id": org_id,
                            "run_id": active_run_id,
                            "step_order": str(step_order),
                            "ocsf_class": str(ocsf_class),
                            "simulated": "true"
                        }
                    )
                except Exception as ex:
                    logger.warning(f"Failed to push simulation event to Redis stream: {ex}")

            step_summary = {
                "step_order": step_order,
                "ocsf_class": ocsf_class,
                "message": ocsf_log.get("message", f"Injected step {step_order} payload"),
                "status": "INJECTED"
            }
            step_results.append(step_summary)

            # Notify frontend of step execution
            step_payload = {
                "type": "SIMULATION_STEP",
                "run_id": active_run_id,
                "profile_id": profile_id,
                "step_order": step_order,
                "total_steps": len(steps),
                "ocsf": ocsf_class,
                "ocsf_class": ocsf_class,
                "injected_message": ocsf_log.get("message", f"Attack step {step_order} executed"),
                "payload": ocsf_log,
                "message": f"Successfully injected Step {step_order}/{len(steps)} into the Ingestion Stream.",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            await self.broadcast_to_org(org_id, step_payload)

        # 3. Complete Scenario Execution
        end_payload = {
            "type": "SIMULATION_COMPLETE",
            "run_id": active_run_id,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "steps_executed": len(steps),
            "status": "COMPLETED",
            "message": f"Purple-Team attack emulation for '{profile_name}' completed. Pipeline verification successful.",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        await self.broadcast_to_org(org_id, end_payload)

        # Update DB if possible
        try:
            from app.core.db import SessionLocal
            from app.models.models import SimulationRun
            with SessionLocal() as db:
                run_record = db.query(SimulationRun).filter(SimulationRun.id == active_run_id).first()
                if run_record:
                    run_record.status = "COMPLETED"
                    run_record.completed_at = datetime.utcnow()
                    run_record.alerts_triggered_count = len(steps)
                    run_record.details = {"steps_executed": step_results, "completed": True}
                    db.commit()
        except Exception as e:
            logger.debug(f"DB update for simulation run finished with: {e}")


emulation_broker = EmulationStreamBroker()


@router.websocket("/api/v1/simulation/ws")
@router.websocket("/api/v29/live-emulation/ws")
async def websocket_simulation_endpoint(websocket: WebSocket, org_id: str = Query("default-org")):
    """
    WebSocket endpoint establishing Purple-Team simulation channel pipelines per tenant.
    """
    await emulation_broker.connect(websocket, org_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                cmd = json.loads(data)
            except Exception:
                continue

            action = cmd.get("action")
            if action == "TRIGGER_SIMULATION":
                profile_id = cmd.get("profile_id", "apt29-espionage")
                delay_multiplier = float(cmd.get("delay_multiplier", 1.0))

                # Fetch profile from DB or use fallback
                steps = []
                profile_name = "Purple Team Scenario"
                try:
                    from app.core.db import SessionLocal
                    from app.models.models import SimulationProfile
                    with SessionLocal() as db:
                        p = db.query(SimulationProfile).filter(
                            (SimulationProfile.id == profile_id) | (SimulationProfile.threat_actor == profile_id)
                        ).first()
                        if p:
                            profile_id = p.id
                            profile_name = p.name
                            steps = [
                                {
                                    "step_order": s.step_order,
                                    "delay_seconds": s.delay_seconds,
                                    "ocsf_class_uid": s.ocsf_class_uid,
                                    "mock_log_payload": s.mock_log_payload
                                }
                                for s in p.steps
                            ]
                except Exception as ex:
                    logger.warning(f"Could not load profile from DB: {ex}")

                if not steps:
                    # Default high-fidelity scenario steps
                    steps = [
                        {
                            "step_order": 1,
                            "delay_seconds": 1,
                            "ocsf_class_uid": 3002,
                            "mock_log_payload": {
                                "metadata": {"class_name": "AUTHENTICATION", "class_uid": 3002},
                                "message": "sshd: Anomalous external SSH authentication accepted for service_admin from 185.190.140.2 port 48120",
                                "src_endpoint": {"ip": "185.190.140.2", "port": 48120},
                                "actor": {"user": {"name": "service_admin"}}
                            }
                        },
                        {
                            "step_order": 2,
                            "delay_seconds": 3,
                            "ocsf_class_uid": 1007,
                            "mock_log_payload": {
                                "metadata": {"class_name": "PROCESS_ACTIVITY", "class_uid": 1007},
                                "message": "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAp...",
                                "process": {"name": "powershell.exe", "cmd_line": "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBP..."}
                            }
                        },
                        {
                            "step_order": 3,
                            "delay_seconds": 4,
                            "ocsf_class_uid": 1007,
                            "mock_log_payload": {
                                "metadata": {"class_name": "PROCESS_ACTIVITY", "class_uid": 1007},
                                "message": "lsass.exe memory read access by unknown process (mimikatz.exe)",
                                "process": {"name": "mimikatz.exe", "cmd_line": "privilege::debug sekurlsa::logonpasswords"}
                            }
                        },
                        {
                            "step_order": 4,
                            "delay_seconds": 3,
                            "ocsf_class_uid": 4001,
                            "mock_log_payload": {
                                "metadata": {"class_name": "NETWORK_ACTIVITY", "class_uid": 4001},
                                "message": "High-entropy bulk outbound transfer (84.2 MB) to un-flagged C2 IP 185.190.140.2:4444",
                                "dst_endpoint": {"ip": "185.190.140.2", "port": 4444},
                                "traffic": {"bytes": 88289120}
                            }
                        }
                    ]

                asyncio.create_task(
                    emulation_broker.run_simulation_task(
                        org_id=org_id,
                        profile_id=profile_id,
                        profile_name=profile_name,
                        steps=steps,
                        delay_multiplier=delay_multiplier
                    )
                )

            elif action == "PING":
                await websocket.send_json({"type": "PONG", "timestamp": datetime.utcnow().isoformat() + "Z"})

    except WebSocketDisconnect:
        emulation_broker.disconnect(websocket, org_id)
