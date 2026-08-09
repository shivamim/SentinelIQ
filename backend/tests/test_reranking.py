"""Tests for the Cohere reranker — graceful fallback, scoring, key availability."""
import asyncio
import sys
import types
from typing import List, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.graph.retrieval import CohereReranker
from app.config import get_settings


# ─── Ensure 'cohere' module is mockable ─────────────────────────────────────
# If the real cohere SDK isn't installed, inject a stub into sys.modules
# so that `patch("cohere.Client")` doesn't raise ModuleNotFoundError.

if "cohere" not in sys.modules:
    _mock_cohere_mod = types.ModuleType("cohere")
    _mock_cohere_mod.Client = MagicMock()
    sys.modules["cohere"] = _mock_cohere_mod


# ─── Sample data for reranker tests ─────────────────────────────────────────

SAMPLE_DOCS = [
    {
        "id": "chunk-1",
        "chunk_text": "PowerShell is a powerful scripting environment used by adversaries for execution.",
        "document_type": "mitre_attack",
        "rrf_score": 0.032,
    },
    {
        "id": "chunk-2",
        "chunk_text": "CVE-2024-3094 is a backdoor in xz utils allowing remote code execution.",
        "document_type": "cve",
        "rrf_score": 0.030,
    },
    {
        "id": "chunk-3",
        "chunk_text": "The root cause of the lateral movement incident was compromised credentials.",
        "document_type": "postmortem",
        "rrf_score": 0.028,
    },
    {
        "id": "chunk-4",
        "chunk_text": "Adversaries use valid accounts to gain persistence and privilege escalation.",
        "document_type": "mitre_attack",
        "rrf_score": 0.027,
    },
    {
        "id": "chunk-5",
        "chunk_text": "CVE-2023-44487 HTTP/2 Rapid Reset denial of service vulnerability.",
        "document_type": "cve",
        "rrf_score": 0.025,
    },
]


def _make_mock_cohere_response(indices_and_scores):
    """Helper to build a mock Cohere rerank response."""
    mock_response = MagicMock()
    mock_results = []
    for idx, score in indices_and_scores:
        mr = MagicMock()
        mr.index = idx
        mr.relevance_score = score
        mock_results.append(mr)
    mock_response.results = mock_results
    return mock_response


class TestRerankerWithCohereKey:
    """Test reranker behavior when Cohere API key is available."""

    @pytest.mark.asyncio
    async def test_reranker_called_when_key_available(self):
        """Reranker should be called when COHERE_API_KEY is set."""
        mock_response = _make_mock_cohere_response([(1, 0.95), (0, 0.85)])
        mock_client = MagicMock()
        mock_client.rerank.return_value = mock_response

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "What is CVE-2024-3094?",
                SAMPLE_DOCS,
                top_n=2,
            )

        # Should have called the Cohere client
        mock_client.rerank.assert_called_once()
        assert len(result) == 2
        # Results should have rerank_score
        for doc in result:
            assert "rerank_score" in doc

    @pytest.mark.asyncio
    async def test_reranked_results_have_rerank_score(self):
        """Reranked results should include rerank_score field."""
        mock_response = _make_mock_cohere_response([(0, 0.9), (1, 0.8), (2, 0.7)])
        mock_client = MagicMock()
        mock_client.rerank.return_value = mock_response

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "PowerShell execution",
                SAMPLE_DOCS,
                top_n=3,
            )

        for doc in result:
            assert "rerank_score" in doc
            assert isinstance(doc["rerank_score"], float)

    @pytest.mark.asyncio
    async def test_reranker_respects_top_n(self):
        """Reranker should return at most top_n results."""
        mock_response = _make_mock_cohere_response([(0, 0.9), (1, 0.8)])
        mock_client = MagicMock()
        mock_client.rerank.return_value = mock_response

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "test query",
                SAMPLE_DOCS,
                top_n=2,
            )

        assert len(result) == 2


class TestRerankerFallback:
    """Test reranker fallback behavior when key is missing or errors occur."""

    @pytest.mark.asyncio
    async def test_reranker_fallback_when_key_missing(self):
        """Reranker should return top_n results as-is when COHERE_API_KEY is empty."""
        with patch("app.graph.retrieval.settings") as mock_settings:
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "test query",
                SAMPLE_DOCS,
                top_n=3,
            )

        # Should return first 3 docs unchanged (no reranking)
        assert len(result) == 3
        for doc in result:
            assert "id" in doc

    @pytest.mark.asyncio
    async def test_reranker_fallback_on_error(self):
        """Reranker should fall back gracefully on any exception."""
        mock_client = MagicMock()
        mock_client.rerank.side_effect = Exception("Cohere API error")

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "test query",
                SAMPLE_DOCS,
                top_n=3,
            )

        # Should fall back to returning first top_n docs
        assert len(result) == 3
        for doc in result:
            assert "id" in doc

    @pytest.mark.asyncio
    async def test_reranker_fallback_on_rate_limit(self):
        """Reranker should fall back gracefully on rate limit errors."""
        mock_client = MagicMock()
        mock_client.rerank.side_effect = Exception("Rate limit exceeded")

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "test query",
                SAMPLE_DOCS,
                top_n=2,
            )

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_reranker_empty_documents(self):
        """Reranker should handle empty document list gracefully."""
        with patch("app.graph.retrieval.settings") as mock_settings:
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "test query",
                [],
                top_n=5,
            )

        assert result == []


class TestRerankerPreservesData:
    """Test that reranker preserves document data while adding scores."""

    @pytest.mark.asyncio
    async def test_reranker_preserves_original_fields(self):
        """Reranked results should preserve all original document fields."""
        mock_response = _make_mock_cohere_response([(0, 0.95)])
        mock_client = MagicMock()
        mock_client.rerank.return_value = mock_response

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank(
                "PowerShell",
                SAMPLE_DOCS[:1],
                top_n=1,
            )

        # Original fields should be preserved
        assert result[0]["id"] == "chunk-1"
        assert result[0]["document_type"] == "mitre_attack"
        assert result[0]["rrf_score"] == 0.032
        # Plus the new rerank_score
        assert result[0]["rerank_score"] == 0.95
