"""Tests for the query rewriter — simple queries pass through, contextual queries get rewritten."""
import asyncio
from typing import List, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.query_rewriter import rewrite_query, _is_simple_factual_query


class TestIsSimpleFactualQuery:
    """Test the heuristic for detecting simple factual queries."""

    def test_cve_id_is_simple(self):
        """CVE identifiers should be detected as simple factual queries."""
        assert _is_simple_factual_query("CVE-2024-3094") is True
        assert _is_simple_factual_query("What is CVE-2023-44487?") is True
        assert _is_simple_factual_query("cve-2021-44228") is True

    def test_mitre_technique_id_is_simple(self):
        """MITRE technique IDs should be detected as simple factual queries."""
        assert _is_simple_factual_query("T1059.001") is True
        assert _is_simple_factual_query("T1078") is True
        assert _is_simple_factual_query("What is T1562?") is True

    def test_very_short_query_is_simple(self):
        """Very short queries (<=3 words) should be considered simple."""
        assert _is_simple_factual_query("PowerShell") is True
        assert _is_simple_factual_query("lateral movement") is True
        assert _is_simple_factual_query("was PowerShell used") is True

    def test_long_natural_language_is_not_simple(self):
        """Longer natural language queries should not be considered simple."""
        assert _is_simple_factual_query("What techniques were used in the lateral movement incident involving the compromised service account?") is False

    def test_mixed_case_cve(self):
        """CVE IDs should be detected regardless of case."""
        assert _is_simple_factual_query("cve-2024-3094") is True
        assert _is_simple_factual_query("Cve-2024-3094") is True


class TestSimpleFactualQueriesPassThrough:
    """Simple factual queries (CVE IDs, technique IDs) should pass through unchanged."""

    @pytest.mark.asyncio
    async def test_cve_id_pass_through(self):
        """A bare CVE ID query should not be rewritten."""
        result = await rewrite_query("CVE-2024-3094")
        assert result == "CVE-2024-3094"

    @pytest.mark.asyncio
    async def test_technique_id_pass_through(self):
        """A bare MITRE technique ID should not be rewritten."""
        result = await rewrite_query("T1059.001")
        assert result == "T1059.001"

    @pytest.mark.asyncio
    async def test_short_query_pass_through(self):
        """Very short queries should pass through without rewriting."""
        result = await rewrite_query("PowerShell")
        assert result == "PowerShell"

    @pytest.mark.asyncio
    async def test_three_word_query_pass_through(self):
        """Three-word queries should pass through without rewriting."""
        result = await rewrite_query("was PowerShell used")
        assert result == "was PowerShell used"


class TestContextualQueryRewriting:
    """Queries with conversation context should be rewritten."""

    @pytest.mark.asyncio
    async def test_query_with_context_gets_rewritten(self):
        """A follow-up question with conversation context should be rewritten by the LLM."""
        # Use a query long enough (>3 words) that it won't be treated as simple,
        # and provide conversation context so it enters the LLM path.
        # The rewrite must be <= 5x the original length to pass the safety check.
        # Original: "Was PowerShell involved in that incident?" (41 chars)
        # Rewrite must be <= 205 chars.
        mock_response = MagicMock()
        mock_response.content = "Was PowerShell used in the lateral movement incident with compromised credentials?"

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response

        conversation_context = [
            {"role": "user", "content": "Tell me about the lateral movement incident"},
            {"role": "assistant", "content": "The lateral movement incident involved compromised service account credentials used via RDP."},
        ]

        query = "Was PowerShell involved in that incident?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query, conversation_context)

        # The query should have been rewritten (different from original)
        assert result != query
        # The rewritten query should contain more specific context
        assert "lateral movement" in result.lower() or "compromised" in result.lower()

    @pytest.mark.asyncio
    async def test_rewrite_resolves_ambiguous_reference(self):
        """The rewriter should resolve ambiguous references using context."""
        # Original: "Was that CVE exploited in any recent incidents?" (47 chars)
        # Rewrite must be <= 235 chars.
        mock_response = MagicMock()
        mock_response.content = "Was CVE-2024-3094 exploited in the supply chain attack we discussed?"

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response

        conversation_context = [
            {"role": "user", "content": "Tell me about the xz utils backdoor"},
            {"role": "assistant", "content": "CVE-2024-3094 is a supply chain compromise in xz utils."},
        ]

        query = "Was that CVE exploited in any recent incidents?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query, conversation_context)

        # Should reference CVE-2024-3094 in the rewrite
        assert "CVE-2024-3094" in result or "supply chain" in result.lower()


class TestEmptyAndBlankQueries:
    """Test handling of empty and blank queries."""

    @pytest.mark.asyncio
    async def test_empty_query_returns_unchanged(self):
        """Empty string query should return unchanged."""
        result = await rewrite_query("")
        assert result == ""

    @pytest.mark.asyncio
    async def test_whitespace_query_returns_unchanged(self):
        """Whitespace-only query should return unchanged."""
        result = await rewrite_query("   ")
        assert result == "   "

    @pytest.mark.asyncio
    async def test_none_like_query(self):
        """Query that is just whitespace should pass through."""
        result = await rewrite_query("\n\t")
        assert result == "\n\t"


class TestFallbackOnLLMFailure:
    """Query rewriting should gracefully fall back on LLM errors."""

    @pytest.mark.asyncio
    async def test_fallback_on_llm_exception(self):
        """If the LLM raises an exception, return the original query."""
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("LLM API error")

        # Need a query that would trigger LLM call (not simple factual)
        query = "What are the common patterns in lateral movement attacks?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query)

        assert result == query

    @pytest.mark.asyncio
    async def test_fallback_on_llm_timeout(self):
        """If the LLM times out, return the original query."""
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = TimeoutError("LLM request timed out")

        query = "How does the defense evasion technique work?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query)

        assert result == query

    @pytest.mark.asyncio
    async def test_fallback_on_groq_key_missing(self):
        """If GROQ_API_KEY is missing, return the original query."""
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = RuntimeError("GROQ_API_KEY is required")

        query = "What techniques involve credential dumping?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query)

        assert result == query

    @pytest.mark.asyncio
    async def test_fallback_on_empty_rewrite(self):
        """If the LLM returns an empty rewrite, fall back to original query."""
        mock_response = MagicMock()
        mock_response.content = ""  # Empty rewrite

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response

        query = "How does defense evasion work?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query)

        assert result == query

    @pytest.mark.asyncio
    async def test_fallback_on_absurdly_long_rewrite(self):
        """If the LLM returns an absurdly long rewrite, fall back to original."""
        mock_response = MagicMock()
        mock_response.content = "A" * 1000  # Way longer than 5x the original

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response

        query = "What is defense evasion?"

        with patch("app.services.query_rewriter._get_llm", return_value=mock_llm), \
             patch("app.services.query_rewriter._llm", None):
            result = await rewrite_query(query)

        # Should fall back since rewrite is > 5x original length
        assert result == query
