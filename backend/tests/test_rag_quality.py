"""Tests for all RAG quality/pre-production fixes.

Covers:
- Real streaming event behavior
- Conversation history loading/saving
- Gold-label evaluation metrics
- Abstention threshold
- Reranker status observability
- Citations and grounding
- Evidence-insufficient behavior
"""
import asyncio
import json
import uuid
from typing import List, Dict, Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest
import pytest_asyncio

from app.services.rag_pipeline import (
    _verify_grounding,
    _build_sources,
    _parse_llm_response,
    _build_prompts,
)
from app.graph.retrieval import CohereReranker


# ─── Helper to make context chunks ──────────────────────────────────────────

def _make_chunk(chunk_id: str, **kwargs) -> Dict[str, Any]:
    """Create a minimal chunk dict with an id."""
    defaults = {
        "id": chunk_id,
        "chunk_text": "sample text",
        "document_id": str(uuid.uuid4()),
        "document_title": "Test Document",
        "document_source": "test",
        "document_type": "unknown",
    }
    defaults.update(kwargs)
    return defaults


# ─── Fix 1: Streaming Event Behavior ────────────────────────────────────────

class TestStreamingEventBehavior:
    """Test that the streaming pipeline yields properly structured events."""

    @pytest.mark.asyncio
    async def test_stream_yields_status_events(self):
        """search_stream should yield status events at start."""
        from app.services.rag_pipeline import RAGPipeline

        mock_db = AsyncMock()
        events = []

        chunk = _make_chunk("c1", rrf_score=0.03)

        with patch("app.services.rag_pipeline.rewrite_query", new_callable=AsyncMock, return_value="test query"), \
             patch("app.services.rag_pipeline.embedding_service") as mock_emb, \
             patch("app.services.rag_pipeline.HybridRetrieval") as mock_hybrid, \
             patch("app.services.rag_pipeline.CohereReranker") as mock_reranker, \
             patch("app.services.rag_pipeline.settings") as mock_settings, \
             patch("app.services.rag_pipeline._get_llm") as mock_get_llm:

            mock_emb.embed.return_value = [[0.1] * 1024]
            mock_hybrid.search_documents = AsyncMock(return_value=[chunk])
            mock_reranker.rerank_with_status = AsyncMock(return_value=([chunk], "skipped"))
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RETRIEVAL_CONFIDENCE_THRESHOLD = 0.0
            mock_settings.RAG_RERANK_TOP_N = 5

            mock_llm = MagicMock()
            mock_chunk1 = MagicMock()
            mock_chunk1.content = "Test answer"
            mock_llm.stream.return_value = iter([mock_chunk1])
            mock_get_llm.return_value = mock_llm

            async for event in RAGPipeline.search_stream(
                mock_db, query="test query"
            ):
                events.append(event)

        # Should have at least one status event
        status_events = [e for e in events if e["type"] == "status"]
        assert len(status_events) >= 1

    @pytest.mark.asyncio
    async def test_stream_yields_done_event(self):
        """search_stream should yield a final done event with complete metadata."""
        from app.services.rag_pipeline import RAGPipeline

        mock_db = AsyncMock()
        events = []
        chunk = _make_chunk("c1", rrf_score=0.03)

        with patch("app.services.rag_pipeline.rewrite_query", new_callable=AsyncMock, return_value="test"), \
             patch("app.services.rag_pipeline.embedding_service") as mock_emb, \
             patch("app.services.rag_pipeline.HybridRetrieval") as mock_hybrid, \
             patch("app.services.rag_pipeline.CohereReranker") as mock_reranker, \
             patch("app.services.rag_pipeline.settings") as mock_settings, \
             patch("app.services.rag_pipeline._get_llm") as mock_get_llm:

            mock_emb.embed.return_value = [[0.1] * 1024]
            mock_hybrid.search_documents = AsyncMock(return_value=[chunk])
            mock_reranker.rerank_with_status = AsyncMock(return_value=([chunk], "skipped"))
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RETRIEVAL_CONFIDENCE_THRESHOLD = 0.0
            mock_settings.RAG_RERANK_TOP_N = 5

            mock_llm = MagicMock()
            mock_chunk = MagicMock()
            mock_chunk.content = '{"answer": "Test answer", "cited_source_ids": []}'
            mock_llm.stream.return_value = iter([mock_chunk])
            mock_get_llm.return_value = mock_llm

            async for event in RAGPipeline.search_stream(
                mock_db, query="test"
            ):
                events.append(event)

        done_events = [e for e in events if e["type"] == "done"]
        assert len(done_events) == 1
        done_data = done_events[0]["data"]
        assert "answer" in done_data
        assert "sources" in done_data
        assert "retrieval_metrics" in done_data
        assert "grounding_status" in done_data


# ─── Fix 2: Conversation History ────────────────────────────────────────────

class TestConversationMemory:
    """Test conversation memory loading and saving."""

    @pytest.mark.asyncio
    async def test_load_history_returns_list(self):
        """load_conversation_history should return a list (empty if no Redis)."""
        from app.services.conversation_memory import load_conversation_history
        with patch("app.services.conversation_memory._get_redis", return_value=None):
            history = await load_conversation_history("test-conv-id")
        assert isinstance(history, list)

    @pytest.mark.asyncio
    async def test_load_history_empty_when_no_redis(self):
        """When Redis is unavailable, history should be empty list."""
        from app.services.conversation_memory import load_conversation_history
        with patch("app.services.conversation_memory._get_redis", return_value=None):
            history = await load_conversation_history("test-conv-id")
        assert history == []

    @pytest.mark.asyncio
    async def test_save_turn_no_error_when_no_redis(self):
        """Saving a turn when Redis is unavailable should not raise."""
        from app.services.conversation_memory import save_conversation_turn
        with patch("app.services.conversation_memory._get_redis", return_value=None):
            await save_conversation_turn("test-conv-id", "user", "test message")

    @pytest.mark.asyncio
    async def test_load_history_with_redis(self):
        """When Redis has history, load_conversation_history should return it."""
        from app.services.conversation_memory import load_conversation_history

        mock_redis = MagicMock()
        mock_redis.llen.return_value = 2
        mock_redis.lrange.return_value = [
            json.dumps({"role": "user", "content": "hello"}),
            json.dumps({"role": "assistant", "content": "hi there"}),
        ]

        with patch("app.services.conversation_memory._get_redis", return_value=mock_redis), \
             patch("app.services.conversation_memory.settings") as mock_settings:
            mock_settings.CONVERSATION_MAX_TURNS = 20
            history = await load_conversation_history("test-conv-id")

        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "hello"
        assert history[1]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_save_turn_with_redis(self):
        """save_conversation_turn should push to Redis list."""
        from app.services.conversation_memory import save_conversation_turn

        mock_redis = MagicMock()
        with patch("app.services.conversation_memory._get_redis", return_value=mock_redis), \
             patch("app.services.conversation_memory.settings") as mock_settings:
            mock_settings.CONVERSATION_MAX_TURNS = 20
            await save_conversation_turn("conv-1", "user", "hello")

        mock_redis.rpush.assert_called_once()
        mock_redis.ltrim.assert_called_once()

    @pytest.mark.asyncio
    async def test_history_truncated_to_max_turns(self):
        """Redis list should be trimmed to CONVERSATION_MAX_TURNS."""
        from app.services.conversation_memory import save_conversation_turn

        mock_redis = MagicMock()
        with patch("app.services.conversation_memory._get_redis", return_value=mock_redis), \
             patch("app.services.conversation_memory.settings") as mock_settings:
            mock_settings.CONVERSATION_MAX_TURNS = 10
            await save_conversation_turn("conv-1", "user", "msg")

        mock_redis.ltrim.assert_called_once()
        call_args = mock_redis.ltrim.call_args
        assert call_args[0][1] == -10
        assert call_args[0][2] == -1


# ─── Fix 3: Gold-Label Evaluation Metrics ───────────────────────────────────

class TestGoldLabelMetrics:
    """Test that evaluation uses gold labels when available."""

    def test_gold_chunk_ids_used_when_present(self):
        """When relevant_chunk_ids are in the entry, they should be used as relevant IDs."""
        # Import directly from the eval module
        sys_path_insert()
        from eval.evaluate_rag import get_relevant_ids

        entry = {
            "relevant_chunk_ids": ["chunk-1", "chunk-3"],
            "relevant_document_ids": ["doc-1"],
            "expected_keywords": ["test"],
            "expected_document_types": ["cve"],
        }
        sources = [
            {"chunk_id": "chunk-1", "document_type": "cve", "chunk_text": "test text"},
            {"chunk_id": "chunk-2", "document_type": "cve", "chunk_text": "other"},
        ]

        relevant_ids, is_gold = get_relevant_ids(entry, sources)
        assert is_gold is True
        assert relevant_ids == {"chunk-1", "chunk-3"}

    def test_estimated_when_no_gold_labels(self):
        """When no gold labels, fall back to estimation and mark as estimated."""
        sys_path_insert()
        from eval.evaluate_rag import get_relevant_ids

        entry = {
            "expected_keywords": ["CVE-2024-3094"],
            "expected_document_types": ["cve"],
        }
        sources = [
            {"chunk_id": "chunk-1", "document_type": "cve", "chunk_text": "CVE-2024-3094 backdoor"},
        ]

        relevant_ids, is_gold = get_relevant_ids(entry, sources)
        assert is_gold is False
        assert len(relevant_ids) > 0

    def test_metrics_with_gold_labels(self):
        """Recall@K with gold labels should be a proper independent benchmark."""
        sys_path_insert()
        from eval.evaluate_rag import recall_at_k, reciprocal_rank, ndcg_at_k

        retrieved = [{"id": "chunk-1"}, {"id": "chunk-2"}, {"id": "chunk-3"}, {"id": "chunk-4"}]
        gold_ids = {"chunk-1", "chunk-3"}

        assert recall_at_k(retrieved, gold_ids, 2) == 0.5
        assert reciprocal_rank(retrieved, gold_ids) == 1.0
        ndcg = ndcg_at_k(retrieved, gold_ids, 4)
        assert 0.0 < ndcg <= 1.0

    def test_dataset_has_gold_label_fields(self):
        """All questions in the dataset should have gold_labeled field."""
        from pathlib import Path
        dataset_path = Path(__file__).resolve().parent.parent / "eval" / "rag_dataset.json"
        with open(dataset_path) as f:
            dataset = json.load(f)
        for entry in dataset:
            assert "relevant_document_ids" in entry
            assert "relevant_chunk_ids" in entry
            assert "gold_labeled" in entry


def sys_path_insert():
    """Ensure eval module is importable."""
    from pathlib import Path
    root = str(Path(__file__).resolve().parent.parent)
    if root not in __import__("sys").path:
        __import__("sys").path.insert(0, root)


# ─── Fix 4: Retrieval Confidence / Abstention ───────────────────────────────

class TestAbstentionThreshold:
    """Test retrieval confidence threshold and evidence-insufficient behavior."""

    @pytest.mark.asyncio
    async def test_abstention_when_below_threshold(self):
        """When top RRF score is below threshold, return evidence_insufficient."""
        from app.services.rag_pipeline import RAGPipeline

        mock_db = AsyncMock()
        chunk = _make_chunk("c1", rrf_score=0.001)

        with patch("app.services.rag_pipeline.rewrite_query", new_callable=AsyncMock, return_value="test"), \
             patch("app.services.rag_pipeline.embedding_service") as mock_emb, \
             patch("app.services.rag_pipeline.HybridRetrieval") as mock_hybrid, \
             patch("app.services.rag_pipeline.settings") as mock_settings:

            mock_emb.embed.return_value = [[0.1] * 1024]
            mock_hybrid.search_documents = AsyncMock(return_value=[chunk])
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RETRIEVAL_CONFIDENCE_THRESHOLD = 0.01

            result = await RAGPipeline.search(mock_db, query="test query")

        assert result["grounding_status"] == "evidence_insufficient"
        assert "cannot answer" in result["answer"].lower() or "insufficient" in result["answer"].lower()

    @pytest.mark.asyncio
    async def test_no_abstention_when_threshold_is_zero(self):
        """When threshold is 0 (default), never abstain."""
        from app.services.rag_pipeline import RAGPipeline

        mock_db = AsyncMock()
        chunk = _make_chunk("c1", rrf_score=0.0001)

        with patch("app.services.rag_pipeline.rewrite_query", new_callable=AsyncMock, return_value="test"), \
             patch("app.services.rag_pipeline.embedding_service") as mock_emb, \
             patch("app.services.rag_pipeline.HybridRetrieval") as mock_hybrid, \
             patch("app.services.rag_pipeline.CohereReranker") as mock_reranker, \
             patch("app.services.rag_pipeline.settings") as mock_settings, \
             patch("app.services.rag_pipeline._generate_answer", new_callable=AsyncMock, return_value=("answer", ["c1"])):

            mock_emb.embed.return_value = [[0.1] * 1024]
            mock_hybrid.search_documents = AsyncMock(return_value=[chunk])
            mock_reranker.rerank_with_status = AsyncMock(return_value=([chunk], "skipped"))
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RETRIEVAL_CONFIDENCE_THRESHOLD = 0.0

            result = await RAGPipeline.search(mock_db, query="test query")

        assert result["grounding_status"] != "evidence_insufficient"


# ─── Fix 5: Reranker Status Observability ───────────────────────────────────

class TestRerankerStatus:
    """Test that reranker status is properly tracked and reported."""

    @pytest.mark.asyncio
    async def test_reranker_status_success(self):
        """When Cohere reranking succeeds, status should be 'success'."""
        mock_response = MagicMock()
        mock_r1 = MagicMock()
        mock_r1.index = 0
        mock_r1.relevance_score = 0.95
        mock_response.results = [mock_r1]

        mock_client = MagicMock()
        mock_client.rerank.return_value = mock_response

        docs = [{"id": "c1", "chunk_text": "test text"}]

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result, status = await CohereReranker.rerank_with_status("query", docs, top_n=1)

        assert status == "success"
        assert len(result) == 1
        assert result[0].get("rerank_score") == 0.95

    @pytest.mark.asyncio
    async def test_reranker_status_skipped(self):
        """When no Cohere key, status should be 'skipped'."""
        docs = [{"id": "c1", "chunk_text": "test text"}]

        with patch("app.graph.retrieval.settings") as mock_settings:
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result, status = await CohereReranker.rerank_with_status("query", docs, top_n=1)

        assert status == "skipped"

    @pytest.mark.asyncio
    async def test_reranker_status_failed(self):
        """When Cohere API fails, status should be 'failed'."""
        mock_client = MagicMock()
        mock_client.rerank.side_effect = Exception("API error")

        docs = [{"id": "c1", "chunk_text": "test text"}]

        with patch("app.graph.retrieval.settings") as mock_settings, \
             patch("cohere.Client", return_value=mock_client):
            mock_settings.COHERE_API_KEY = "test-key"
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result, status = await CohereReranker.rerank_with_status("query", docs, top_n=1)

        assert status == "failed"
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_reranker_backward_compat(self):
        """rerank() (without status) should still work for backward compat."""
        docs = [{"id": "c1", "chunk_text": "test text"}]

        with patch("app.graph.retrieval.settings") as mock_settings:
            mock_settings.COHERE_API_KEY = ""
            mock_settings.RERANKER_MODEL = "rerank-v3-enterprise"

            result = await CohereReranker.rerank("query", docs, top_n=1)

        assert len(result) == 1


# ─── Fix 6: Grounding Improvements ──────────────────────────────────────────

class TestGroundingImprovements:
    """Test improved grounding verification with evidence_insufficient and no fabrication."""

    def test_evidence_insufficient_when_answer_says_so(self):
        """When the answer indicates insufficient evidence, return evidence_insufficient."""
        chunks = [_make_chunk("c1")]
        answer = "The sources do not contain enough information to answer this question."
        result = _verify_grounding(answer, chunks, ["c1"])
        assert result == "evidence_insufficient"

    def test_evidence_insufficient_on_cannot_answer(self):
        """'cannot answer' in answer → evidence_insufficient."""
        chunks = [_make_chunk("c1")]
        answer = "I cannot answer this question with the available evidence."
        result = _verify_grounding(answer, chunks, [])
        assert result == "evidence_insufficient"

    def test_fabricated_ids_detected(self):
        """Citations with IDs not in the retrieved set should be detected."""
        chunks = [_make_chunk("chunk-1")]
        answer = "According to sources..."
        cited_ids = ["chunk-1", "fabricated-id"]
        result = _verify_grounding(answer, chunks, cited_ids)
        assert result == "partially_grounded"

    def test_all_fabricated_ids_ungrounded(self):
        """If ALL cited IDs are fabricated, result is ungrounded."""
        chunks = [_make_chunk("chunk-1")]
        answer = "According to sources..."
        cited_ids = ["fake-1", "fake-2"]
        result = _verify_grounding(answer, chunks, cited_ids)
        assert result == "ungrounded"

    def test_never_fabricate_sources(self):
        """_build_sources should never produce citations for non-existent chunks."""
        assert _build_sources([]) == []
        chunks = [_make_chunk("c1")]
        sources = _build_sources(chunks)
        assert len(sources) == 1
        assert sources[0]["chunk_id"] == "c1"

    def test_empty_answer_is_evidence_insufficient(self):
        """Empty answer should be evidence_insufficient."""
        chunks = [_make_chunk("c1")]
        result = _verify_grounding("", chunks, ["c1"])
        assert result == "evidence_insufficient"


# ─── Fix 6b: Citation Integrity ─────────────────────────────────────────────

class TestCitationIntegrity:
    """Test that citations only reference actually retrieved chunks."""

    def test_citations_only_from_retrieved(self):
        """Every source citation must correspond to a retrieved chunk."""
        chunks = [
            _make_chunk("c1", document_id="doc-1"),
            _make_chunk("c2", document_id="doc-1"),
        ]
        sources = _build_sources(chunks)
        source_chunk_ids = {s["chunk_id"] for s in sources}
        input_chunk_ids = {"c1", "c2"}
        assert source_chunk_ids == input_chunk_ids

    def test_no_sources_for_empty_chunks(self):
        """No chunks → no sources."""
        assert _build_sources([]) == []

    def test_source_fields_complete(self):
        """Every source should have all required fields."""
        chunks = [_make_chunk("c1")]
        sources = _build_sources(chunks)
        required = {"document_id", "chunk_id", "title", "source", "document_type", "score", "chunk_text"}
        for s in sources:
            assert required.issubset(set(s.keys()))
