import asyncio
import json
import logging
import time
from typing import Dict, Set, Optional, Any, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status, HTTPException
from jose import JWTError
import redis
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.security import decode_access_token
from app.core.deps import get_current_user
from app.models.models import User
from app.services.metrics import AgentHealthTracker, IngestionMetricsTracker
from app.schemas.schemas import (
    RealtimeMetricsOut,
    AgentHeartbeatRequest,
    AgentHeartbeatOut,
    FleetDeviceStatusOut,
    SimulateLogRequest,
    AlertLockRequest,
    AlertLockOut,
    WebSocketStatusOut,
)

logger = logging.getLogger("threat-analyser.ws")
router = APIRouter(prefix="", tags=["websockets & realtime telemetry"])

# Sync Redis client for REST metrics
sync_redis = redis.from_url(settings.REDIS_URL)
health_tracker = AgentHealthTracker(sync_redis)
metrics_tracker = IngestionMetricsTracker(sync_redis)


class WebSocketManager:
    """
    Active WebSocket Connection Pool categorized by Tenant/Organization ID.
    Ensures multi-tenant isolation and concurrent frame broadcasting.
    """

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.alert_locks: Dict[str, Dict[str, Any]] = {}

    async def connect(self, tenant_id: str, websocket: WebSocket):
        await websocket.accept()
        if tenant_id not in self.active_connections:
            self.active_connections[tenant_id] = set()
        self.active_connections[tenant_id].add(websocket)
        logger.info(
            f"WebSocket established for tenant: {tenant_id}. Total active on tenant: {len(self.active_connections[tenant_id])}"
        )

    def disconnect(self, tenant_id: str, websocket: WebSocket):
        if tenant_id in self.active_connections:
            self.active_connections[tenant_id].discard(websocket)
            if not self.active_connections[tenant_id]:
                del self.active_connections[tenant_id]
        logger.info(f"WebSocket closed for tenant: {tenant_id}")

    async def broadcast_to_tenant(self, tenant_id: str, message: dict):
        if tenant_id not in self.active_connections:
            return
        payload = json.dumps(message)
        dead_sockets = set()
        for ws in self.active_connections[tenant_id]:
            try:
                await ws.send_text(payload)
            except Exception as e:
                logger.warning(f"Error sending message to client: {e}")
                dead_sockets.add(ws)

        for ws in dead_sockets:
            self.disconnect(tenant_id, ws)

    def get_stats(self) -> Dict[str, Any]:
        total_connections = sum(len(s) for s in self.active_connections.values())
        return {
            "active_connections_count": total_connections,
            "active_tenants_connected": len(self.active_connections),
            "tenants": list(self.active_connections.keys()),
        }


ws_manager = WebSocketManager()


async def redis_event_broadcaster(redis_url: str):
    """
    Subscribes to Redis dynamic tenant channels and dispatches events
    to connected WebSocket client sets in real-time.
    """
    logger.info(f"Connecting Real-Time Redis Broadcast Event Bus: {redis_url}")
    while True:
        try:
            r = aioredis.from_url(redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.psubscribe("threat-analyser:tenant:*")
            logger.info("Real-Time Redis Broadcast Event Bus fully active.")

            async for message in pubsub.listen():
                if message["type"] == "pmessage":
                    channel = message["channel"]  # threat-analyser:tenant:{org_id}:{event_type}
                    parts = channel.split(":")
                    if len(parts) >= 4:
                        tenant_id = parts[2]
                        event_type = parts[3]
                        try:
                            data = json.loads(message["data"])
                            broadcast_payload = {
                                "event": event_type,
                                "payload": data,
                                "timestamp": time.time(),
                            }
                            await ws_manager.broadcast_to_tenant(tenant_id, broadcast_payload)
                        except json.JSONDecodeError:
                            logger.error(f"Malformed JSON payload on channel: {channel}")
        except asyncio.CancelledError:
            logger.info("Broadcaster task cleanly cancelled.")
            break
        except Exception as e:
            logger.error(f"Redis Pub/Sub connection error in broadcaster: {e}. Retrying in 2s...")
            await asyncio.sleep(2.0)


# =========================================================================
# WebSockets Endpoint
# =========================================================================

@router.websocket("/ws/stream")
async def handle_websocket_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    WebSocket entry point for real-time log, alert, and health telemetry.
    Secured via query-parameter JWT token verification.
    """
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        payload = decode_access_token(token)
        tenant_id = payload.get("org_id") or payload.get("sub") or "default-tenant"
        user_name = payload.get("email") or payload.get("sub") or "Anonymous Analyst"
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    except Exception as e:
        logger.error(f"JWT decode error in WebSocket handshake: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(tenant_id, websocket)

    # Send initial welcome banner with telemetry sync
    try:
        welcome_payload = {
            "event": "connected",
            "payload": {
                "message": "Connected to Threat Analyser Sub-Millisecond Telemetry Mesh (v12)",
                "tenant_id": tenant_id,
                "server_time": time.time(),
                "active_locks": ws_manager.alert_locks.get(tenant_id, {}),
            },
        }
        await websocket.send_text(json.dumps(welcome_payload))
    except Exception:
        pass

    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                control_msg = json.loads(raw_data)
            except Exception:
                continue

            action = control_msg.get("action")

            if action == "acquire_lock":
                alert_id = control_msg.get("alert_id")
                if alert_id:
                    if tenant_id not in ws_manager.alert_locks:
                        ws_manager.alert_locks[tenant_id] = {}
                    ws_manager.alert_locks[tenant_id][alert_id] = {
                        "locked_by": user_name,
                        "locked_at": time.time(),
                    }
                    lock_broadcast = {
                        "event": "alert_locked",
                        "payload": {
                            "alert_id": alert_id,
                            "locked_by": user_name,
                            "locked_at": time.time(),
                        },
                    }
                    await ws_manager.broadcast_to_tenant(tenant_id, lock_broadcast)

            elif action == "release_lock":
                alert_id = control_msg.get("alert_id")
                if alert_id and tenant_id in ws_manager.alert_locks:
                    ws_manager.alert_locks[tenant_id].pop(alert_id, None)
                    unlock_broadcast = {
                        "event": "alert_unlocked",
                        "payload": {"alert_id": alert_id},
                    }
                    await ws_manager.broadcast_to_tenant(tenant_id, unlock_broadcast)

            elif action == "ping":
                await websocket.send_text(
                    json.dumps({"event": "pong", "payload": {"timestamp": time.time()}})
                )

    except WebSocketDisconnect:
        ws_manager.disconnect(tenant_id, websocket)
    except Exception as e:
        logger.error(f"WebSocket error on stream: {e}")
        ws_manager.disconnect(tenant_id, websocket)


# =========================================================================
# REST Endpoints for Metrics, Heartbeats & Simulators
# =========================================================================

@router.get("/ws/status", response_model=WebSocketStatusOut)
def get_websocket_server_status(user: User = Depends(get_current_user)):
    """
    Returns live WebSocket server connection statistics and supported event types.
    """
    stats = ws_manager.get_stats()
    return WebSocketStatusOut(
        active_connections_count=stats["active_connections_count"],
        active_tenants_connected=stats["active_tenants_connected"],
        redis_pubsub_channel_pattern="threat-analyser:tenant:{org_id}:*",
        server_status="ONLINE_BROADCASTING",
        supported_stream_events=[
            "raw_logs",
            "alerts",
            "metrics_update",
            "alert_locked",
            "alert_unlocked",
            "agent_heartbeat",
        ],
    )


@router.post("/ws/simulate-log")
def simulate_log_stream_packet(
    payload: SimulateLogRequest,
    user: User = Depends(get_current_user),
):
    """
    Dispatches synthetic high-frequency OCSF logs over Redis Pub/Sub for live testing.
    """
    org_id = user.org_id
    start_time = time.time()
    
    logs_generated = []
    for i in range(payload.count):
        sample_log = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "class_name": payload.class_name,
            "severity_id": payload.severity_id,
            "message": f"{payload.message} [seq={i+1}/{payload.count}]",
            "device": {"hostname": payload.hostname or "prod-api-gateway-01"},
            "actor": {"user": {"name": user.email.split("@")[0]}},
            "activity_id": 1,
            "category_uid": 1,
            "metadata": {
                "version": "1.1.0",
                "simulated": True,
                "latency_ms": round((time.time() - start_time) * 1000 + 4.2, 2),
            },
        }
        logs_generated.append(sample_log)

        # Publish to Redis channel: threat-analyser:tenant:{org_id}:raw_logs
        try:
            sync_redis.publish(
                f"threat-analyser:tenant:{org_id}:raw_logs",
                json.dumps(sample_log),
            )
        except Exception as e:
            logger.error(f"Failed to publish simulated log to Redis: {e}")

    # Track metrics in Redis Sorted Sets
    latency_ms = round((time.time() - start_time) * 1000 + 5.0, 2)
    metrics_tracker.record_ingest(org_id, payload.count, latency_ms)

    return {
        "status": "DISPATCHED",
        "count_sent": len(logs_generated),
        "target_channel": f"threat-analyser:tenant:{org_id}:raw_logs",
        "pipeline_latency_ms": latency_ms,
        "sample": logs_generated[0] if logs_generated else None,
    }


@router.post("/ws/co-triage-lock", response_model=AlertLockOut)
def acquire_co_triage_lock(
    payload: AlertLockRequest,
    user: User = Depends(get_current_user),
):
    """
    Acquires an analyst lock on an incident alert and broadcasts it to all connected analysts.
    """
    org_id = user.org_id
    now = time.time()
    user_display = user.email.split("@")[0]

    if org_id not in ws_manager.alert_locks:
        ws_manager.alert_locks[org_id] = {}

    ws_manager.alert_locks[org_id][payload.alert_id] = {
        "locked_by": user_display,
        "locked_at": now,
    }

    # Broadcast over Redis Pub/Sub
    lock_event = {
        "alert_id": payload.alert_id,
        "locked_by": user_display,
        "locked_at": now,
    }
    try:
        sync_redis.publish(
            f"threat-analyser:tenant:{org_id}:alert_locked",
            json.dumps(lock_event),
        )
    except Exception as e:
        logger.error(f"Error publishing lock event: {e}")

    return AlertLockOut(
        alert_id=payload.alert_id,
        locked_by=user_display,
        locked_at=now,
        status="LOCKED",
    )


@router.get("/metrics/realtime", response_model=RealtimeMetricsOut)
def get_realtime_ingestion_metrics(user: User = Depends(get_current_user)):
    """
    Calculates live sliding 60s window Events Per Second (EPS) and pipeline latency.
    """
    stats = metrics_tracker.get_realtime_stats(user.org_id)
    return RealtimeMetricsOut(**stats)


@router.post("/metrics/heartbeat", response_model=AgentHeartbeatOut)
def record_agent_heartbeat(
    payload: AgentHeartbeatRequest,
    user: User = Depends(get_current_user),
):
    """
    Sub-second Redis hash heartbeat endpoint with TTL expiration.
    """
    res = health_tracker.record_heartbeat(
        org_id=user.org_id,
        device_id=payload.device_id,
        hostname=payload.hostname,
        os_version=payload.os_version or "Linux x86_64",
        agent_version=payload.agent_version or "v12.0.4-stream",
    )
    return AgentHeartbeatOut(**res)


@router.get("/metrics/fleet-status", response_model=List[FleetDeviceStatusOut])
def get_fleet_agent_status(user: User = Depends(get_current_user)):
    """
    Returns dynamic fleet agent online/offline states from Redis TTL storage.
    """
    fleet = health_tracker.get_fleet_status(user.org_id)
    return [FleetDeviceStatusOut(**d) for d in fleet]
