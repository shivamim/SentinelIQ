"""SentinelIQ — FastAPI entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth, alerts, incidents, review_queue, audit, webhooks, reports, chat, documents
from app.database import engine
from app.config import get_settings
from app.services.neo4j_service import neo4j_service

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — validate production config, then serve."""
    # Validate required production environment variables
    settings.validate_production()
    yield
    await engine.dispose()
    await neo4j_service.close()


app = FastAPI(
    title="SentinelIQ",
    description="Incident Correlation & Triage Copilot",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration from environment
# When origins is "*" (wildcard), allow_credentials MUST be False per CORS spec
_cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
_is_wildcard = "*" in _cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _is_wildcard else _cors_origins,
    allow_credentials=not _is_wildcard,  # Must be False when origins is "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(review_queue.router)
app.include_router(audit.router)
app.include_router(webhooks.router)
app.include_router(reports.router)
app.include_router(chat.router)
app.include_router(documents.router)


@app.get("/health")
async def health():
    return {"status": "ok", "app": "SentinelIQ"}


@app.get("/health/neo4j")
async def health_neo4j():
    """
    Neo4j health check endpoint.
    
    Returns connection status and node counts:
    - connected: bool
    - database: str
    - alert_count: int
    - asset_count: int
    - incident_count: int
    - technique_count: int
    """
    try:
        health_info = await neo4j_service.health_check()
        return health_info
    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }
