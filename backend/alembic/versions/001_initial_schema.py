"""Initial schema — SentinelIQ

Revision ID: 001_initial
Revises: None
Create Date: 2025-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pgvector extension
    op.execute('CREATE EXTENSION IF NOT EXISTS vector')

    # Users table (Supabase Auth)
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('supabase_uid', sa.Text, unique=True, nullable=False),
        sa.Column('email', sa.Text, unique=True, nullable=False),
        sa.Column('role', sa.Text, nullable=False, server_default='analyst'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # Assets table
    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('hostname', sa.Text, nullable=False),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('asset_type', sa.Text),
        sa.Column('criticality', sa.Text),
        sa.Column('owner_team', sa.Text),
        sa.Column('environment', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # Alerts table (with tsvector for BM25)
    op.create_table(
        'alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('source', sa.Text, nullable=False),
        sa.Column('raw_alert', postgresql.JSONB, nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id')),
        sa.Column('alert_type', sa.Text),
        sa.Column('severity', sa.Text),
        sa.Column('ioc_ip', postgresql.INET),
        sa.Column('ioc_domain', sa.Text),
        sa.Column('ioc_hash', sa.Text),
        sa.Column('status', sa.Text, server_default='new'),
        sa.Column('search_vector', postgresql.TSVECTOR),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # GIN index on alerts tsvector for BM25
    op.execute('CREATE INDEX idx_alerts_search ON alerts USING GIN (search_vector)')
    op.create_index('idx_alerts_asset', 'alerts', ['asset_id'])
    op.create_index('idx_alerts_ioc_ip', 'alerts', ['ioc_ip'])

    # Incidents table
    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('title', sa.Text, nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.Text),
        sa.Column('status', sa.Text, server_default='open'),
        sa.Column('opened_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('closed_at', sa.DateTime(timezone=True)),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
    )

    # Postmortems table (with tsvector for BM25)
    op.create_table(
        'postmortems',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id')),
        sa.Column('summary', sa.Text, nullable=False),
        sa.Column('root_cause', sa.Text),
        sa.Column('remediation', sa.Text),
        sa.Column('tags', postgresql.ARRAY(sa.Text)),
        sa.Column('search_vector', postgresql.TSVECTOR),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # GIN index on postmortems tsvector for BM25
    op.execute('CREATE INDEX idx_postmortems_search ON postmortems USING GIN (search_vector)')

    # CVE References table (with tsvector for BM25)
    op.create_table(
        'cve_references',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('cve_id', sa.Text, unique=True, nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('cvss_score', sa.Numeric),
        sa.Column('affected_products', postgresql.ARRAY(sa.Text)),
        sa.Column('published_date', sa.Date),
        sa.Column('search_vector', postgresql.TSVECTOR),
    )

    # GIN index on cve_references tsvector for BM25
    op.execute('CREATE INDEX idx_cve_references_search ON cve_references USING GIN (search_vector)')

    # Embedding tables (pgvector — 1024 dims for Voyage voyage-3)
    op.create_table(
        'cve_embeddings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('cve_id', sa.Text, sa.ForeignKey('cve_references.cve_id')),
        sa.Column('chunk_text', sa.Text),
        sa.Column('embedding', sa.Text),  # Will be replaced with Vector(1024) via raw SQL
    )
    op.execute('ALTER TABLE cve_embeddings ALTER COLUMN embedding TYPE VECTOR(1024) USING embedding::vector')

    op.create_table(
        'postmortem_embeddings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('postmortem_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('postmortems.id')),
        sa.Column('chunk_text', sa.Text),
        sa.Column('embedding', sa.Text),
    )
    op.execute('ALTER TABLE postmortem_embeddings ALTER COLUMN embedding TYPE VECTOR(1024) USING embedding::vector')

    op.create_table(
        'mitre_technique_embeddings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('technique_id', sa.Text),
        sa.Column('chunk_text', sa.Text),
        sa.Column('embedding', sa.Text),
    )
    op.execute('ALTER TABLE mitre_technique_embeddings ALTER COLUMN embedding TYPE VECTOR(1024) USING embedding::vector')

    # HNSW indexes for vector similarity search
    # HNSW works on empty tables (unlike IVFFlat which requires training data first)
    op.execute('CREATE INDEX idx_cve_embeddings_vector ON cve_embeddings USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)')
    op.execute('CREATE INDEX idx_postmortem_embeddings_vector ON postmortem_embeddings USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)')
    op.execute('CREATE INDEX idx_mitre_embeddings_vector ON mitre_technique_embeddings USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)')

    # Correlation results table
    op.create_table(
        'correlation_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('alert_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('alerts.id')),
        sa.Column('matched_incident_ids', postgresql.ARRAY(postgresql.UUID(as_uuid=True))),
        sa.Column('matched_cve_ids', postgresql.ARRAY(sa.Text)),
        sa.Column('matched_mitre_techniques', postgresql.ARRAY(sa.Text)),
        sa.Column('reasoning_text', sa.Text),
        sa.Column('confidence_score', sa.Numeric),
        sa.Column('verdict', sa.Text),
        sa.Column('grounding_passed', sa.Boolean),
        sa.Column('retry_count', sa.Integer, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # Audit log table
    op.create_table(
        'audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('actor', sa.Text, nullable=False),
        sa.Column('action', sa.Text, nullable=False),
        sa.Column('entity_type', sa.Text),
        sa.Column('entity_id', postgresql.UUID(as_uuid=True)),
        sa.Column('metadata', postgresql.JSONB),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )


def downgrade() -> None:
    op.drop_table('audit_log')
    op.drop_table('correlation_results')
    op.drop_table('mitre_technique_embeddings')
    op.drop_table('postmortem_embeddings')
    op.drop_table('cve_embeddings')
    op.drop_table('cve_references')
    op.drop_table('postmortems')
    op.drop_table('incidents')
    op.drop_table('alerts')
    op.drop_table('assets')
    op.drop_table('users')
    op.execute('DROP EXTENSION IF EXISTS vector')
