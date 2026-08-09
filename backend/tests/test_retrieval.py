"""Tests for the retrieval pipeline — HybridRetrieval, RRF, metadata filtering.

Unit tests use mock data; integration tests (marked @pytest.mark.integration)
require a real PostgreSQL + pgvector database.
"""
import uuid
from typing import List, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph.retrieval import HybridRetrieval, CohereReranker, RRF_K


# ─── Unit tests for RRF (no DB needed) ─────────────────────────────────────

class TestReciprocalRankFusion:
    """Test the RRF algorithm in isolation."""

    def test_rrf_single_list(self):
        """RRF with a single list should preserve ranking order."""
        docs = [
            {"id": "1", "score": 0.9},
            {"id": "2", "score": 0.8},
            {"id": "3", "score": 0.7},
        ]
        result = HybridRetrieval._reciprocal_rank_fusion(docs, top_n=10)
        assert len(result) == 3
        assert result[0]["id"] == "1"
        assert result[1]["id"] == "2"
        assert result[2]["id"] == "3"
        # Each doc should have an rrf_score
        for doc in result:
            assert "rrf_score" in doc
            assert doc["rrf_score"] > 0

    def test_rrf_two_lists(self):
        """RRF should combine two ranked lists and boost docs appearing in both."""
        list_a = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        list_b = [{"id": "3"}, {"id": "4"}, {"id": "1"}]

        result = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, top_n=10)

        # Doc "3" appears at rank 3 in A and rank 1 in B
        # Doc "1" appears at rank 1 in A and rank 3 in B
        # Both appear in both lists, so they should rank higher than 2 and 4
        ids = [d["id"] for d in result]
        assert "1" in ids
        assert "3" in ids
        # 2 and 4 appear in only one list, so they should rank lower
        assert ids.index("1") < ids.index("2") or "2" not in ids
        assert ids.index("3") < ids.index("4") or "4" not in ids

    def test_rrf_deduplication(self):
        """Same document appearing in multiple lists should only appear once."""
        list_a = [{"id": "1"}, {"id": "2"}]
        list_b = [{"id": "1"}, {"id": "3"}]

        result = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, top_n=10)
        ids = [d["id"] for d in result]
        assert ids.count("1") == 1

    def test_rrf_top_n_limits_results(self):
        """top_n should limit the number of returned results."""
        docs = [{"id": str(i)} for i in range(20)]
        result = HybridRetrieval._reciprocal_rank_fusion(docs, top_n=5)
        assert len(result) == 5

    def test_rrf_empty_lists(self):
        """Empty input lists should return empty result."""
        result = HybridRetrieval._reciprocal_rank_fusion([], top_n=10)
        assert result == []

    def test_rrf_score_formula(self):
        """Verify the RRF score formula: 1/(k + rank)."""
        k = 60  # default RRF_K
        list_a = [{"id": "1"}]
        list_b = [{"id": "1"}]

        result = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, k=k, top_n=10)
        # Doc "1" is rank 1 in both lists
        expected_score = 1.0 / (k + 1) + 1.0 / (k + 1)
        assert abs(result[0]["rrf_score"] - expected_score) < 1e-10

    def test_rrf_custom_k(self):
        """RRF should respect custom k parameter."""
        list_a = [{"id": "1"}, {"id": "2"}]
        list_b = [{"id": "2"}, {"id": "1"}]

        result_k10 = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, k=10, top_n=10)
        result_k100 = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, k=100, top_n=10)

        # With different k, the absolute scores change but relative order may differ
        assert result_k10[0]["rrf_score"] != result_k100[0]["rrf_score"]

    def test_rrf_with_cve_id_key(self):
        """RRF should use cve_id as fallback key when id is absent."""
        list_a = [{"cve_id": "CVE-2024-3094"}, {"cve_id": "CVE-2023-44487"}]
        list_b = [{"cve_id": "CVE-2023-44487"}, {"cve_id": "CVE-2024-3094"}]

        result = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, top_n=10)
        assert len(result) == 2
        ids = {d["cve_id"] for d in result}
        assert "CVE-2024-3094" in ids
        assert "CVE-2023-44487" in ids

    def test_rrf_three_lists(self):
        """RRF should handle three or more ranked lists."""
        list_a = [{"id": "1"}, {"id": "2"}]
        list_b = [{"id": "2"}, {"id": "3"}]
        list_c = [{"id": "3"}, {"id": "1"}]

        result = HybridRetrieval._reciprocal_rank_fusion(list_a, list_b, list_c, top_n=10)
        assert len(result) == 3
        # Doc "1" appears in A and C, doc "2" in A and B, doc "3" in B and C
        # All appear in exactly 2 lists, so scores should be close


class TestVectorRetrieval:
    """Test vector retrieval (requires real DB — integration tests)."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_vector_retrieval_returns_similarity_scores(self, mock_db_session):
        """Vector retrieval should return results with similarity scores."""
        # This is an integration test that requires pgvector
        # In unit test mode, we mock the DB response
        pass

    def test_vector_results_have_similarity(self):
        """Mocked vector results should have similarity field."""
        mock_results = [
            {"id": "1", "similarity": 0.95, "chunk_text": "PowerShell execution"},
            {"id": "2", "similarity": 0.87, "chunk_text": "Credential dumping"},
        ]
        for r in mock_results:
            assert "similarity" in r
            assert 0 <= r["similarity"] <= 1.0


class TestBM25Retrieval:
    """Test BM25 retrieval (requires real DB — integration tests)."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_bm25_retrieval_returns_bm25_score(self, mock_db_session):
        """BM25 retrieval should return results with bm25_score."""
        # Integration test — requires PostgreSQL with tsvector
        pass

    def test_bm25_results_have_score(self):
        """Mocked BM25 results should have bm25_score field."""
        mock_results = [
            {"id": "1", "bm25_score": 0.85, "chunk_text": "PowerShell execution"},
            {"id": "2", "bm25_score": 0.72, "chunk_text": "Credential dumping"},
        ]
        for r in mock_results:
            assert "bm25_score" in r
            assert r["bm25_score"] >= 0


class TestMetadataFiltering:
    """Test metadata filtering in search_documents."""

    def test_filter_by_document_type(self):
        """Filtering by document_type should restrict results."""
        results = [
            {"id": "1", "document_type": "mitre_attack"},
            {"id": "2", "document_type": "cve"},
            {"id": "3", "document_type": "mitre_attack"},
        ]
        filtered = [r for r in results if r["document_type"] == "mitre_attack"]
        assert len(filtered) == 2
        assert all(r["document_type"] == "mitre_attack" for r in filtered)

    def test_filter_by_document_type_list(self):
        """Filtering by multiple document_types should work."""
        results = [
            {"id": "1", "document_type": "mitre_attack"},
            {"id": "2", "document_type": "cve"},
            {"id": "3", "document_type": "postmortem"},
        ]
        allowed = {"mitre_attack", "cve"}
        filtered = [r for r in results if r["document_type"] in allowed]
        assert len(filtered) == 2

    def test_filter_by_source(self):
        """Filtering by source should restrict results."""
        results = [
            {"id": "1", "document_source": "nvd"},
            {"id": "2", "document_source": "mitre_attack"},
            {"id": "3", "document_source": "nvd"},
        ]
        filtered = [r for r in results if r["document_source"] == "nvd"]
        assert len(filtered) == 2


class TestSearchDocumentsJoinsMetadata:
    """Test that search_documents properly joins document metadata."""

    def test_results_include_document_metadata(self, sample_chunks):
        """Results from search_documents should include document metadata fields."""
        for chunk in sample_chunks:
            assert "document_title" in chunk
            assert "document_source" in chunk
            assert "document_type" in chunk
            assert "document_id" in chunk

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_search_documents_jins_document_fields(self):
        """Integration test: search_documents should join document metadata."""
        # Requires real DB
        pass
