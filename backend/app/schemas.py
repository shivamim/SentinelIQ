"""Pydantic schemas for request/response validation."""
from typing import Literal, Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID


# ---------- Auth ----------
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


# ---------- Assets ----------
class AssetOut(BaseModel):
    id: UUID
    hostname: str
    ip_address: Optional[str]
    asset_type: Optional[str]
    criticality: Optional[str]
    owner_team: Optional[str]
    environment: Optional[str]

    class Config:
        from_attributes = True


# ---------- Alerts ----------
class AlertIngest(BaseModel):
    source: str
    raw_alert: dict
    asset_id: Optional[UUID] = None
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    ioc_ip: Optional[str] = None
    ioc_domain: Optional[str] = None
    ioc_hash: Optional[str] = None


class AlertOut(BaseModel):
    id: UUID
    source: str
    raw_alert: dict
    asset_id: Optional[UUID]
    alert_type: Optional[str]
    severity: Optional[str]
    ioc_ip: Optional[str]
    ioc_domain: Optional[str]
    ioc_hash: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Incidents ----------
class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[UUID] = None


class IncidentOut(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    severity: Optional[str]
    status: str
    opened_at: datetime
    closed_at: Optional[datetime]
    assigned_to: Optional[UUID]

    class Config:
        from_attributes = True


class PostmortemCreate(BaseModel):
    summary: str
    root_cause: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None


class PostmortemOut(BaseModel):
    id: UUID
    incident_id: UUID
    summary: str
    root_cause: Optional[str]
    remediation: Optional[str]
    tags: Optional[List[str]]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Correlation ----------
class CorrelationResultOut(BaseModel):
    id: UUID
    alert_id: UUID
    matched_incident_ids: Optional[List[UUID]]
    matched_cve_ids: Optional[List[str]]
    matched_mitre_techniques: Optional[List[str]]
    reasoning_text: Optional[str]
    confidence_score: Optional[float]
    verdict: Optional[Literal["known_pattern", "novel", "uncertain"]]
    grounding_passed: Optional[bool]
    retry_count: int
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Review Queue ----------
class ReviewQueueItem(BaseModel):
    alert_id: UUID
    alert_type: Optional[str]
    severity: Optional[str]
    verdict: Optional[str]
    confidence_score: Optional[float]
    reasoning_text: Optional[str]
    created_at: datetime


class ReviewResolve(BaseModel):
    verdict: Literal["known_pattern", "novel", "uncertain"]
    reasoning_override: Optional[str] = None


# ---------- Audit ----------
class AuditLogOut(BaseModel):
    id: UUID
    actor: str
    action: str
    entity_type: Optional[str]
    entity_id: Optional[UUID]
    metadata_json: Optional[dict] = Field(None, alias="metadata")
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


# ---------- Parsers ----------
class ParsedAlerts(BaseModel):
    source: str
    alerts: List[dict]
    parser_type: str
    count: int


# ---------- Webhooks ----------
class WebhookPayload(BaseModel):
    connector_id: Optional[str] = None
    event_type: str = "alert"
    payload: dict


# ---------- Chat / RAG ----------
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


# ---------- Documents ----------
class DocumentIngest(BaseModel):
    title: str
    source: str
    source_url: Optional[str] = None
    document_type: str  # mitre_attack, cve, incident, postmortem, markdown, json
    content: str
    metadata_json: Optional[dict] = Field(None, alias="metadata")

    class Config:
        populate_by_name = True


class DocumentChunkOut(BaseModel):
    id: UUID
    document_id: UUID
    chunk_index: int
    chunk_text: str
    metadata_json: Optional[dict] = Field(None, alias="metadata")
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class DocumentOut(BaseModel):
    id: UUID
    title: str
    source: str
    source_url: Optional[str]
    document_type: str
    content: str
    metadata_json: Optional[dict] = Field(None, alias="metadata")
    created_at: datetime
    updated_at: Optional[datetime]
    chunks: Optional[List[DocumentChunkOut]] = None

    class Config:
        from_attributes = True
        populate_by_name = True
