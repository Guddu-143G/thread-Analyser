from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.db import Base, engine
from app.models import models, sbom  # noqa: F401 ensures models are registered with Base
from app.api.routes import (
    auth, devices, iocs, rules, ingest, alerts,
    dashboard, events, audit_logs, federation, compliance,
    enclave, archive, deception, simulation,
    fhe, honeynet, hunting, sbom as sbom_route, containment,
    pqc, gnn, twin, forensics, exchange, inventory, bluetooth, tpm, chaos,
    consensus, ws, sovereign, v15_defense, v16_defense, v17_neon_mesh, v18_live_response, v19_fleet_control, v20_edge_mesh, v21_mobile_forensics,
    v23_spatial_ledger, v24_baseband_ledger, v25_cognitive_matrix, v26_provenance_soar,
    v27_ml_anomaly, v28_federated_ml, v29_simulation_stg, v30_cyber_range
)
from app.api import ws_provenance_stream, ws_ml, ws_federation, ws_simulation, ws_cyber_range

app = FastAPI(title=settings.APP_NAME, version="30.0.0")



origins = ["*"] if settings.CORS_ORIGINS == "*" else settings.CORS_ORIGINS.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(iocs.router)
app.include_router(rules.router)
app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(audit_logs.router)
app.include_router(federation.router)
app.include_router(compliance.router)
app.include_router(enclave.router)
app.include_router(archive.router)
app.include_router(deception.router)
app.include_router(simulation.router)
app.include_router(fhe.router)
app.include_router(honeynet.router)
app.include_router(hunting.router)
app.include_router(sbom_route.router)
app.include_router(containment.router)
app.include_router(pqc.router)
app.include_router(gnn.router)
app.include_router(twin.router)
app.include_router(forensics.router)
app.include_router(exchange.router)
app.include_router(inventory.router)
app.include_router(bluetooth.router)
app.include_router(tpm.router)
app.include_router(chaos.router)
app.include_router(consensus.router)
app.include_router(ws.router, prefix="/api")
app.include_router(sovereign.router)
app.include_router(v15_defense.router)
app.include_router(v16_defense.router)
app.include_router(v17_neon_mesh.router, prefix="/api")
app.include_router(v18_live_response.router, prefix="/api")
app.include_router(v19_fleet_control.router, prefix="/api")
app.include_router(v20_edge_mesh.router, prefix="/api")
app.include_router(v21_mobile_forensics.router, prefix="/api")
app.include_router(v23_spatial_ledger.router, prefix="/api")
app.include_router(v24_baseband_ledger.router, prefix="/api")
app.include_router(v24_baseband_ledger.realtime_router, prefix="/api")
app.include_router(v25_cognitive_matrix.router, prefix="/api")
app.include_router(v25_cognitive_matrix.v1_stream_router, prefix="/api")
app.include_router(v26_provenance_soar.router, prefix="/api")
app.include_router(ws_provenance_stream.router)
app.include_router(v27_ml_anomaly.router, prefix="/api/v27", tags=["V27 ML Anomaly Engine"])
app.include_router(ws_ml.router)
app.include_router(v28_federated_ml.router, prefix="/api/v28", tags=["V28 Federated Learning Mesh"])
app.include_router(ws_federation.router)
app.include_router(v29_simulation_stg.router, prefix="/api/v29", tags=["V29 Sovereign STG & Purple-Team"])
app.include_router(ws_simulation.router)
app.include_router(v30_cyber_range.router, prefix="/api/v30", tags=["V30 Cyber Range & GSDT"])
app.include_router(v30_cyber_range.router, prefix="/api/v1/range", tags=["V30 Cyber Range V1 Alias"])
app.include_router(ws_cyber_range.router)







@app.on_event("startup")
async def on_startup():
    Base.metadata.create_all(bind=engine)
    # Start Real-Time Redis Pub/Sub Broadcaster in background
    import asyncio
    asyncio.create_task(ws.redis_event_broadcaster(settings.REDIS_URL))
    # Safe incremental schema upgrades for existing postgres volume
    with engine.connect() as conn:
        conn.execute(
            Base.metadata.tables["organizations"].select().limit(0)
        )
        statements = [
            "ALTER TABLE tenant_technology_inventory ADD COLUMN IF NOT EXISTS runtime VARCHAR;",
            "ALTER TABLE tenant_technology_inventory ADD COLUMN IF NOT EXISTS category VARCHAR;",
            "ALTER TABLE tenant_technology_inventory ADD COLUMN IF NOT EXISTS environment VARCHAR DEFAULT 'production';",
            "ALTER TABLE tenant_technology_inventory ADD COLUMN IF NOT EXISTS path VARCHAR;"
        ]
        for stmt in statements:
            try:
                from sqlalchemy import text
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass


@app.get("/api/health")
def health():
    return {"status": "ok", "service": settings.APP_NAME}
