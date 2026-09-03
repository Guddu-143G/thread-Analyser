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
    consensus, ws, sovereign, v15_defense, v16_defense, v17_neon_mesh, v18_live_response, v19_fleet_control, v20_edge_mesh
)

app = FastAPI(title=settings.APP_NAME, version="20.0.0")

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
