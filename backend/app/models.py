"""SQLAlchemy ORM models — SentinelIQ schema with tsvector for BM25."""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    JSON,
    ARRAY,
    Numeric,
    Text,
    Boolean,
    Integer,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, INET, DATE, TSVECTOR
from sqlalchemy.orm import relationship
from pgvector.sqlalchemy import Vector
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    supabase_uid = Column(Text, unique=True, nullable=False)
    email = Column(Text, unique=True, nullable=False)
    role = Column(Text, nullable=False, default="analyst")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(Text, nullable=False)
    ip_address = Column(INET)
    asset_type = Column(Text)
    criticality = Column(Text)
    owner_team = Column(Text)
    environment = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(Text, nullable=False)
    raw_alert = Column(JSON, nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"))
    alert_type = Column(Text)
    severity = Column(Text)
    ioc_ip = Column(INET)
    ioc_domain = Column(Text)
    ioc_hash = Column(Text)
    status = Column(Text, default="new")
    search_vector = Column(TSVECTOR)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    asset = relationship("Asset")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(Text)
    status = Column(Text, default="open")
    opened_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    closed_at = Column(DateTime(timezone=True))
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class Postmortem(Base):
    __tablename__ = "postmortems"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    summary = Column(Text, nullable=False)
    root_cause = Column(Text)
    remediation = Column(Text)
    tags = Column(ARRAY(Text))
    search_vector = Column(TSVECTOR)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class CveReference(Base):
    __tablename__ = "cve_references"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(Text, unique=True, nullable=False)
    description = Column(Text)
    cvss_score = Column(Numeric)
    affected_products = Column(ARRAY(Text))
    published_date = Column(DATE)
    search_vector = Column(TSVECTOR)


class CveEmbedding(Base):
    __tablename__ = "cve_embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(Text, ForeignKey("cve_references.cve_id"))
    chunk_text = Column(Text)
    embedding = Column(Vector(1024))  # Voyage voyage-3 = 1024 dims


class PostmortemEmbedding(Base):
    __tablename__ = "postmortem_embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    postmortem_id = Column(UUID(as_uuid=True), ForeignKey("postmortems.id"))
    chunk_text = Column(Text)
    embedding = Column(Vector(1024))


class MitreTechniqueEmbedding(Base):
    __tablename__ = "mitre_technique_embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id = Column(Text)
    chunk_text = Column(Text)
    embedding = Column(Vector(1024))


class CorrelationResult(Base):
    __tablename__ = "correlation_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    matched_incident_ids = Column(ARRAY(UUID(as_uuid=True)))
    matched_cve_ids = Column(ARRAY(Text))
    matched_mitre_techniques = Column(ARRAY(Text))
    reasoning_text = Column(Text)
    confidence_score = Column(Numeric)
    verdict = Column(Text)
    grounding_passed = Column(Boolean)
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    entity_type = Column(Text)
    entity_id = Column(UUID(as_uuid=True))
    metadata_json = Column("metadata", JSON)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class Document(Base):
    __tablename__ = "documents"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(Text, nullable=False)
    source = Column(Text, nullable=False)
    source_url = Column(Text)
    document_type = Column(Text, nullable=False)  # mitre_attack, cve, incident, postmortem, markdown, json
    content = Column(Text, nullable=False)
    metadata_json = Column("metadata", JSON)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class DocumentChunk(Base):
    __tablename__ = "document_chunks"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(UUID(as_uuid=True), ForeignKey("documents.id"))
    chunk_index = Column(Integer, nullable=False)
    chunk_text = Column(Text, nullable=False)
    embedding = Column(Vector(1024))
    metadata_json = Column("metadata", JSON)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
