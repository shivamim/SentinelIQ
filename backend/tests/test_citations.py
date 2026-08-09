"""Tests for source citations — verify citations correspond to actually retrieved chunks."""
import uuid
from typing import List, Dict, Any

import pytest

from app.services.rag_pipeline import _build_sources


# ─── Sample chunks for citation tests ───────────────────────────────────────

def _make_chunk(
    chunk_id: str = None,
    document_id: str = None,
    chunk_text: str = "Sample chunk text.",
    document_title: str = "Untitled",
    document_source: str = "unknown",
    document_type: str = "unknown",
    rrf_score: float = 0.03,
    similarity: float = 0.85,
    rerank_score: float = None,
) -> Dict[str, Any]:
    """Helper to create a chunk dict matching the structure from retrieval."""
    chunk = {
        "id": chunk_id or str(uuid.uuid4()),
        "document_id": document_id or str(uuid.uuid4()),
        "chunk_text": chunk_text,
        "document_title": document_title,
        "document_source": document_source,
        "document_type": document_type,
        "rrf_score": rrf_score,
        "similarity": similarity,
    }
    if rerank_score is not None:
        chunk["rerank_score"] = rerank_score
    return chunk


class TestCitationsCorrespondToRetrieved:
    """Citations should correspond to actually retrieved chunks — no fabrication."""

    def test_citations_match_retrieved_chunks(self):
        """Each citation should reference a chunk that was actually retrieved."""
        chunks = [
            _make_chunk(chunk_id="chunk-1", document_id="doc-1"),
            _make_chunk(chunk_id="chunk-2", document_id="doc-1"),
            _make_chunk(chunk_id="chunk-3", document_id="doc-2"),
        ]
        sources = _build_sources(chunks)

        # Every source should have a chunk_id that matches one of the input chunks
        source_chunk_ids = {s["chunk_id"] for s in sources}
        input_chunk_ids = {str(c["id"]) for c in chunks}
        assert source_chunk_ids == input_chunk_ids

    def test_no_extra_citations(self):
        """_build_sources should not produce citations for non-existent chunks."""
        chunks = [_make_chunk(chunk_id="chunk-1")]
        sources = _build_sources(chunks)
        assert len(sources) == 1
        assert sources[0]["chunk_id"] == "chunk-1"

    def test_no_fabricated_citations(self):
        """_build_sources should not fabricate citations not in the input."""
        chunks = []
        sources = _build_sources(chunks)
        assert len(sources) == 0


class TestCitationRequiredFields:
    """Each citation should have all required fields."""

    def test_citation_has_required_fields(self):
        """Each citation must have: document_id, chunk_id, title, source, document_type, score."""
        chunks = [
            _make_chunk(
                chunk_id="chunk-1",
                document_id="doc-1",
                document_title="MITRE T1059.001",
                document_source="mitre_attack",
                document_type="mitre_attack",
            ),
        ]
        sources = _build_sources(chunks)

        required_fields = {"document_id", "chunk_id", "title", "source", "document_type", "score"}
        for source in sources:
            for field in required_fields:
                assert field in source, f"Missing required field: {field}"

    def test_citation_field_types(self):
        """Citation fields should have the correct types."""
        chunks = [
            _make_chunk(
                chunk_id="chunk-1",
                document_id="doc-1",
                rrf_score=0.032,
            ),
        ]
        sources = _build_sources(chunks)

        source = sources[0]
        assert isinstance(source["document_id"], str)
        assert isinstance(source["chunk_id"], str)
        assert isinstance(source["title"], str)
        assert isinstance(source["source"], str)
        assert isinstance(source["document_type"], str)
        assert isinstance(source["score"], (int, float))

    def test_citation_score_uses_best_available(self):
        """Citation score should use rrf_score > rerank_score > similarity (as coded in _build_sources).

        The actual priority in _build_sources is:
            chunk.get("rrf_score", chunk.get("rerank_score", chunk.get("similarity", 0.0)))
        So rrf_score takes priority if present, then rerank_score, then similarity.
        """
        # With rrf_score present (takes priority even if rerank_score exists)
        chunk_with_rrf = _make_chunk(
            chunk_id="chunk-1",
            rrf_score=0.032,
            similarity=0.85,
            rerank_score=0.95,
        )
        sources = _build_sources([chunk_with_rrf])
        # rrf_score takes priority per current code
        assert abs(sources[0]["score"] - 0.032) < 1e-10

        # Without rrf_score, falls back to rerank_score
        chunk_with_rerank_only = {
            "id": "chunk-r",
            "document_id": "doc-r",
            "chunk_text": "text",
            "document_title": "Test",
            "document_source": "test",
            "document_type": "test",
            "rerank_score": 0.95,
            "similarity": 0.80,
        }
        sources = _build_sources([chunk_with_rerank_only])
        assert abs(sources[0]["score"] - 0.95) < 1e-10

        # Without rrf_score or rerank_score, falls back to similarity
        chunk_with_similarity_only = {
            "id": "chunk-s",
            "document_id": "doc-s",
            "chunk_text": "text",
            "document_title": "Test",
            "document_source": "test",
            "document_type": "test",
            "similarity": 0.80,
        }
        sources = _build_sources([chunk_with_similarity_only])
        assert abs(sources[0]["score"] - 0.80) < 1e-10


class TestCitationChunkTextPreview:
    """Test chunk_text preview truncation in citations."""

    def test_short_text_not_truncated(self):
        """Chunk text shorter than 200 chars should not be truncated."""
        short_text = "This is a short chunk text."
        chunk = _make_chunk(chunk_text=short_text)
        sources = _build_sources([chunk])
        assert sources[0]["chunk_text"] == short_text

    def test_long_text_truncated(self):
        """Chunk text longer than 200 chars should be truncated with '...'."""
        long_text = "A" * 300
        chunk = _make_chunk(chunk_text=long_text)
        sources = _build_sources([chunk])
        assert len(sources[0]["chunk_text"]) == 203  # 200 + "..."
        assert sources[0]["chunk_text"].endswith("...")

    def test_exactly_200_chars_not_truncated(self):
        """Chunk text of exactly 200 chars should not be truncated."""
        text_200 = "A" * 200
        chunk = _make_chunk(chunk_text=text_200)
        sources = _build_sources([chunk])
        assert sources[0]["chunk_text"] == text_200


class TestCitationDocumentTypePreserved:
    """Test that document_type is preserved in citations."""

    def test_mitre_attack_type(self):
        """MITRE ATT&CK document type should be preserved."""
        chunk = _make_chunk(document_type="mitre_attack", document_title="T1059.001")
        sources = _build_sources([chunk])
        assert sources[0]["document_type"] == "mitre_attack"

    def test_cve_type(self):
        """CVE document type should be preserved."""
        chunk = _make_chunk(document_type="cve", document_title="CVE-2024-3094")
        sources = _build_sources([chunk])
        assert sources[0]["document_type"] == "cve"

    def test_postmortem_type(self):
        """Postmortem document type should be preserved."""
        chunk = _make_chunk(document_type="postmortem", document_title="Incident Review")
        sources = _build_sources([chunk])
        assert sources[0]["document_type"] == "postmortem"
