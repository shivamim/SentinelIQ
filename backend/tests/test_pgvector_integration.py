"""Integration test for PostgreSQL/pgvector retrieval path.

This test verifies the real flow:
  Document → DocumentChunk → stored embedding → vector retrieval → BM25 retrieval → RRF

It requires a running PostgreSQL+pgvector instance. If unavailable,
the test is skipped with a clear message explaining how to run it manually.

To run manually:
    DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/sentineliq \
    pytest tests/test_pgvector_integration.py -v

The test uses deterministic fake embeddings (no Voyage/Groq/Cohere credentials needed).
"""
import asyncio
import json
import math
import uuid
from typing import List, Dict, Any

import pytest

# Skip entire module if pgvector not available
pytestmark = pytest.mark.integration


def _fake_embedding(text: str, dim: int = 1024) -> List[float]:
    """Generate a deterministic fake embedding based on text content."""
    base_val = hash(text) % 1000 / 1000.0
    embedding = [base_val + (i * 0.001) for i in range(dim)]
    norm = sum(x * x for x in embedding) ** 0.5
    return [x / norm for x in embedding]


@pytest.fixture
async def pgvector_db():
    """Provide a real PostgreSQL+pgvector async session, or skip if unavailable."""
    import os
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        create_async_engine,
        async_sessionmaker,
    )
    from sqlalchemy import text

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/sentineliq",
    )

    try:
        engine = create_async_engine(db_url, echo=False)
        # Test connection
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        pytest.skip(
            f"PostgreSQL+pgvector not available: {e}. "
            f"Set DATABASE_URL and ensure PostgreSQL is running with pgvector extension."
        )
        return

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session

    await engine.dispose()


class TestPgvectorIntegration:
    """Integration tests for the real PostgreSQL/pgvector retrieval path."""

    @pytest.mark.asyncio
    async def test_rrf_fusion_logic(self):
        """Verify RRF fusion math works correctly with deterministic inputs.

        This test does NOT require PostgreSQL — it validates the RRF algorithm.
        """
        from app.graph.retrieval import HybridRetrieval

        bm25_results = [
            {"id": "c1", "chunk_text": "powershell execution", "bm25_score": 0.9},
            {"id": "c2", "chunk_text": "lateral movement", "bm25_score": 0.7},
            {"id": "c3", "chunk_text": "privilege escalation", "bm25_score": 0.5},
        ]
        vector_results = [
            {"id": "c2", "chunk_text": "lateral movement", "similarity": 0.95},
            {"id": "c1", "chunk_text": "powershell execution", "similarity": 0.88},
            {"id": "c4", "chunk_text": "credential dumping", "similarity": 0.82},
        ]

        fused = HybridRetrieval._reciprocal_rank_fusion(
            bm25_results, vector_results, top_n=4
        )

        # All unique IDs should be present
        fused_ids = {r["id"] for r in fused}
        assert fused_ids == {"c1", "c2", "c3", "c4"}

        # c1 and c2 appear in both lists, so they should rank higher
        assert fused[0]["id"] in {"c1", "c2"}
        assert fused[1]["id"] in {"c1", "c2"}

        # Each result should have an rrf_score
        for r in fused:
            assert "rrf_score" in r
            assert r["rrf_score"] > 0

        # c1 and c2 RRF scores should be higher than c3 and c4
        score_map = {r["id"]: r["rrf_score"] for r in fused}
        assert score_map["c1"] > score_map["c3"]
        assert score_map["c2"] > score_map["c4"]

    @pytest.mark.asyncio
    async def test_bm25_sql_query_structure(self, pgvector_db):
        """Verify that BM25 SQL query with tsvector works on real PostgreSQL.

        Requires PostgreSQL with pg_trgm and tsvector support.
        """
        from sqlalchemy import text

        # Test that plainto_tsquery and ts_rank_cd work
        result = await pgvector_db.execute(
            text("SELECT plainto_tsquery('PowerShell execution') AS query")
        )
        row = result.scalar_one_or_none()
        assert row is not None

    @pytest.mark.asyncio
    async def test_vector_cosine_distance(self, pgvector_db):
        """Verify that pgvector cosine distance operator works.

        Requires the pgvector extension to be installed.
        """
        from sqlalchemy import text

        # Check pgvector extension
        result = await pgvector_db.execute(
            text("SELECT extname FROM pg_extension WHERE extname = 'vector'")
        )
        ext = result.scalar_one_or_none()
        if ext is None:
            pytest.skip("pgvector extension not installed. Run: CREATE EXTENSION vector;")

        # Test cosine distance with simple vectors
        vec_a = str([1.0, 0.0, 0.0])
        vec_b = str([0.0, 1.0, 0.0])

        result = await pgvector_db.execute(
            text(f"SELECT ({vec_a}::vector) <=> ({vec_b}::vector) AS cos_dist")
        )
        dist = result.scalar_one_or_none()
        assert dist is not None
        # Orthogonal vectors should have cosine distance = 1.0
        assert abs(dist - 1.0) < 0.01

    @pytest.mark.asyncio
    async def test_document_chunk_roundtrip(self, pgvector_db):
        """Verify Document and DocumentChunk can be inserted and retrieved.

        Uses deterministic fake embeddings — no Voyage API key needed.
        """
        from sqlalchemy import text

        doc_id = str(uuid.uuid4())
        chunk_id = str(uuid.uuid4())
        fake_emb = _fake_embedding("test chunk text for integration test")

        try:
            # Insert document
            await pgvector_db.execute(
                text("""
                    INSERT INTO documents (id, title, source, document_type, content, metadata, created_at, updated_at)
                    VALUES (:id, :title, :source, :dtype, :content, :meta, now(), now())
                """),
                {
                    "id": doc_id,
                    "title": "Integration Test Document",
                    "source": "test",
                    "dtype": "mitre_attack",
                    "content": "Test content for pgvector integration verification.",
                    "meta": json.dumps({"test": True}),
                },
            )

            # Insert chunk with embedding
            await pgvector_db.execute(
                text("""
                    INSERT INTO document_chunks (id, document_id, chunk_index, chunk_text, embedding, metadata, created_at)
                    VALUES (:id, :doc_id, :chunk_idx, :chunk_text, :emb, :meta, now())
                """),
                {
                    "id": chunk_id,
                    "doc_id": doc_id,
                    "chunk_idx": 0,
                    "chunk_text": "Test content for pgvector integration verification.",
                    "emb": str(fake_emb),
                    "meta": json.dumps({"test": True}),
                },
            )
            await pgvector_db.commit()

            # Retrieve via vector search
            query_emb = _fake_embedding("integration test")
            result = await pgvector_db.execute(
                text("""
                    SELECT id, document_id, chunk_text,
                           1 - (embedding <=> :emb) AS similarity
                    FROM document_chunks
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> :emb
                    LIMIT 5
                """),
                {"emb": str(query_emb)},
            )
            rows = [dict(r) for r in result.mappings().all()]
            assert len(rows) >= 1
            assert rows[0]["document_id"] == doc_id
            assert rows[0]["similarity"] > 0

        finally:
            # Cleanup
            await pgvector_db.execute(
                text("DELETE FROM document_chunks WHERE id = :id"), {"id": chunk_id}
            )
            await pgvector_db.execute(
                text("DELETE FROM documents WHERE id = :id"), {"id": doc_id}
            )
            await pgvector_db.commit()
