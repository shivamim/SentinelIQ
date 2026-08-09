"""SentinelIQ — FastAPI entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer

from app.routers import auth, alerts, incidents, review_queue, audit, webhooks, reports, chat, documents
from app.database import engine
from app.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — validate production config, then serve."""
    # Validate required production environment variables
    settings.validate_production()
    yield
    await engine.dispose()


# Configure OpenAPI security scheme for HTTP Bearer auth
# This correctly represents that we expect a Supabase JWT in Authorization: Bearer header
security_scheme = HTTPBearer(auto_error=False)

app = FastAPI(
    title="SentinelIQ",
    description="Incident Correlation & Triage Copilot",
    version="1.0.0",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "auth", "description": "Authentication endpoints"},
        {"name": "alerts", "description": "Alert management"},
        {"name": "incidents", "description": "Incident management"},
        {"name": "review-queue", "description": "Review queue"},
        {"name": "reports", "description": "Reports and dashboards"},
        {"name": "chat", "description": "Chat interface"},
        {"name": "documents", "description": "Document management"},
        {"name": "audit", "description": "Audit trail"},
        {"name": "webhooks", "description": "Webhook endpoints"},
    ],
)


def custom_openapi():
    """Customize OpenAPI schema to use HTTP Bearer auth."""
    if app.openapi_schema:
        return app.openapi_schema
    
    from fastapi.openapi.utils import get_openapi
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    
    # Set up HTTP Bearer security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your Supabase access token (JWT). Login is handled by Supabase Auth on the frontend.",
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

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
