"""Pydantic schemas for request/response validation."""

from typing import Literal, Optional, List
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, IPvAnyAddress


# ============================================================
# Auth
# ============================================================

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SupabaseLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: UUID
    supabase_uid: str
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Assets
# ============================================================

class AssetOut(BaseModel):
    id: UUID
    hostname: str
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    criticality: Optional[str] = None
    owner_team: Optional[str] = None
    environment: Optional[str] = None

    class Config:
        from_attributes = True


# ============================================================
# Alerts
# ============================================================

class AlertIngest(BaseModel):
    source: str
    raw_alert: dict
    asset_id: Optional[UUID] = None
    alert_type: Optional[str] = None
    severity: Optional[str] = None

    # PostgreSQL INET -> IPv4Address / IPv6Address
    ioc_ip: Optional[IPvAnyAddress] = None

    ioc_domain: Optional[str] = None
    ioc_hash: Optional[str] = None


class AlertOut(BaseModel):
    id: UUID
    source: str
    raw_alert: dict
    asset_id: Optional[UUID] = None
    alert_type: Optional[str] = None
    severity: Optional[str] = None

    # PostgreSQL INET returns an IP address object.
    # IPvAnyAddress allows both IPv4 and IPv6.
    ioc_ip: Optional[IPvAnyAddress] = None

    ioc_domain: Optional[str] = None
    ioc_hash: Optional[str] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Incidents
# ============================================================

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[UUID] = None


class IncidentOut(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    status: str
    opened_at: datetime
    closed_at: Optional[datetime] = None
    assigned_to: Optional[UUID] = None

    class Config:
        from_attributes = True


# ============================================================
# Postmortems
# ============================================================

class PostmortemCreate(BaseModel):
    summary: str
    root_cause: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None


class PostmortemOut(BaseModel):
    id: UUID
    incident_id: UUID
    summary: str
    root_cause: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Correlation
# ============================================================

class CorrelationResultOut(BaseModel):
    id: UUID
    alert_id: UUID
    matched_incident_ids: Optional[List[UUID]] = None
    matched_cve_ids: Optional[List[str]] = None
    matched_mitre_techniques: Optional[List[str]] = None
    reasoning_text: Optional[str] = None
    confidence_score: Optional[float] = None
    verdict: Optional[
        Literal["known_pattern", "novel", "uncertain"]
    ] = None
    grounding_passed: Optional[bool] = None
    retry_count: int
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Review Queue
# ============================================================

class ReviewQueueItem(BaseModel):
    alert_id: UUID
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None
    confidence_score: Optional[float] = None
    reasoning_text: Optional[str] = None
    created_at: datetime


class ReviewResolve(BaseModel):
    verdict: Literal["known_pattern", "novel", "uncertain"]
    reasoning_override: Optional[str] = None


# ============================================================
# Audit
# ============================================================

class AuditLogOut(BaseModel):
    id: UUID
    actor: str
    action: str
    entity_type: Optional[str] = None
    entity_id: Optional[UUID] = None
    metadata_json: Optional[dict] = Field(
        default=None,
        alias="metadata",
    )
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


# ============================================================
# Parsers
# ============================================================

class ParsedAlerts(BaseModel):
    source: str
    alerts: List[dict]
    parser_type: str
    count: int


# ============================================================
# Webhooks
# ============================================================

class WebhookPayload(BaseModel):
    connector_id: Optional[str] = None
    event_type: str = "alert"
    payload: dict


# ============================================================
# Chat / RAG
# ============================================================

class ChatRequest(BaseModel):
    query: str
    conversation_id: Optional[str] = None
    filters: Optional[dict] = None


class SourceCitation(BaseModel):
    document_id: str
    chunk_id: str
    title: str
    source: str
    document_type: str
    score: float
    chunk_text: str


class RetrievalMetrics(BaseModel):
    chunks_retrieved: int
    reranked_count: int
    sources_used: int
    vector_score_range: str
    bm25_score_range: str
    rrf_score_range: str
    reranker: str = "none"
    reranker_status: str = "skipped"


class ChatResponse(BaseModel):
    answer: str
    sources: List[SourceCitation]
    retrieval_metrics: RetrievalMetrics
    grounding_status: str
    conversation_id: str


# ============================================================
# Documents
# ============================================================

class DocumentIngest(BaseModel):
    title: str
    source: str
    source_url: Optional[str] = None
    document_type: str
    content: str
    metadata_json: Optional[dict] = Field(
        default=None,
        alias="metadata",
    )

    class Config:
        populate_by_name = True


class DocumentChunkOut(BaseModel):
    id: UUID
    document_id: UUID
    chunk_index: int
    chunk_text: str
    metadata_json: Optional[dict] = Field(
        default=None,
        alias="metadata",
    )
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class DocumentOut(BaseModel):
    id: UUID
    title: str
    source: str
    source_url: Optional[str] = None
    document_type: str
    content: str
    metadata_json: Optional[dict] = Field(
        default=None,
        alias="metadata",
    )
    created_at: datetime
    updated_at: Optional[datetime] = None
    chunks: Optional[List[DocumentChunkOut]] = None

    class Config:
        from_attributes = True
        populate_by_name = True
