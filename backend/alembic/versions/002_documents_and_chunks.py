"""Add documents and document_chunks tables with HNSW + GIN indexes

Revision ID: 002_documents_and_chunks
Revises: 001_initial
Create Date: 2025-01-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_documents_and_chunks'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── documents table ────────────────────────────────────────────────
    op.create_table(
        'documents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('title', sa.Text, nullable=False),
        sa.Column('source', sa.Text, nullable=False),
        sa.Column('source_url', sa.Text),
        sa.Column('document_type', sa.Text, nullable=False),
        sa.Column('content', sa.Text, nullable=False),
        sa.Column('metadata', postgresql.JSONB),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # ── document_chunks table ──────────────────────────────────────────
    op.create_table(
        'document_chunks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('document_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('documents.id')),
        sa.Column('chunk_index', sa.Integer, nullable=False),
        sa.Column('chunk_text', sa.Text, nullable=False),
        sa.Column('embedding', sa.Text),  # Will be cast to VECTOR(1024)
        sa.Column('metadata', postgresql.JSONB),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )

    # Cast embedding column to VECTOR(1024) for pgvector
    op.execute('ALTER TABLE document_chunks ALTER COLUMN embedding TYPE VECTOR(1024) USING embedding::vector')

    # ── Indexes ────────────────────────────────────────────────────────

    # HNSW index on embedding for vector similarity search
    # HNSW works on empty tables (unlike IVFFlat which needs data first)
    op.execute(
        'CREATE INDEX idx_document_chunks_embedding_hnsw '
        'ON document_chunks USING hnsw (embedding vector_cosine_ops) '
        'WITH (m = 16, ef_construction = 64)'
    )

    # Add a search_vector TSVECTOR column for BM25 full-text search on chunk_text
    op.execute('ALTER TABLE document_chunks ADD COLUMN search_vector TSVECTOR')

    # GIN index on search_vector for BM25
    op.execute('CREATE INDEX idx_document_chunks_search_gin ON document_chunks USING GIN (search_vector)')

    # Index on document_id for foreign key lookups
    op.create_index('idx_document_chunks_document_id', 'document_chunks', ['document_id'])

    # Index on document_type for filtering (via documents join)
    op.create_index('idx_documents_document_type', 'documents', ['document_type'])

    # Trigger to auto-populate search_vector from chunk_text on insert/update
    op.execute("""
        CREATE OR REPLACE FUNCTION document_chunks_search_vector_update()
        RETURNS trigger AS $$
        BEGIN
            NEW.search_vector := to_tsvector('english', COALESCE(NEW.chunk_text, ''));
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_document_chunks_search_vector
        BEFORE INSERT OR UPDATE OF chunk_text ON document_chunks
        FOR EACH ROW
        EXECUTE FUNCTION document_chunks_search_vector_update();
    """)


def downgrade() -> None:
    # Drop trigger and function
    op.execute('DROP TRIGGER IF EXISTS trg_document_chunks_search_vector ON document_chunks')
    op.execute('DROP FUNCTION IF EXISTS document_chunks_search_vector_update()')

    # Drop indexes (HNSW and GIN are dropped with the table, but be explicit)
    op.execute('DROP INDEX IF EXISTS idx_document_chunks_embedding_hnsw')
    op.execute('DROP INDEX IF EXISTS idx_document_chunks_search_gin')
    op.execute('DROP INDEX IF EXISTS idx_document_chunks_document_id')
    op.execute('DROP INDEX IF EXISTS idx_documents_document_type')

    # Drop tables
    op.drop_table('document_chunks')
    op.drop_table('documents')
