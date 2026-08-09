"""Query rewriting service — uses Groq LLM to rewrite vague/ambiguous queries.

For simple factual queries, preserves the original intent.
For follow-up questions with conversation context, expands ambiguous references
(e.g., "Was PowerShell involved?" → "Was PowerShell involved in the incident
about lateral movement from 10.0.1.5 that we discussed?").
"""
import json
from typing import List, Dict, Any, Optional

from app.config import get_settings

settings = get_settings()

# Lazy-init Groq client (same pattern as nodes.py)
_llm = None


def _get_llm():
    """Lazy-initialize the Groq ChatGroq instance."""
    global _llm
    if _llm is not None:
        return _llm
    if not settings.GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is required for query rewriting. "
            "Set the GROQ_API_KEY environment variable."
        )
    from langchain_groq import ChatGroq
    _llm = ChatGroq(
        model=settings.GROQ_MODEL,
        groq_api_key=settings.GROQ_API_KEY,
        temperature=0.0,  # Deterministic rewriting
        max_tokens=512,
    )
    return _llm


async def rewrite_query(
    query: str,
    conversation_context: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Rewrite a user query for better retrieval, using conversation context.

    Args:
        query: The raw user query string.
        conversation_context: Optional list of prior conversation turns, each
            a dict with 'role' (user/assistant) and 'content' keys.

    Returns:
        A rewritten query string optimized for retrieval. Falls back to the
        original query if rewriting fails for any reason.
    """
    if not query or not query.strip():
        return query

    # If no conversation context, check if the query is simple enough to
    # pass through without rewriting (short, specific queries like "CVE-2024-1234")
    if not conversation_context:
        if _is_simple_factual_query(query):
            return query

    try:
        llm = _get_llm()
        from langchain_core.messages import SystemMessage, HumanMessage

        system_prompt = """You are a query rewriting assistant for a cybersecurity knowledge base.
Your job is to rewrite the user's query to be more effective for information retrieval.

Rules:
1. For simple factual queries (e.g., "What is CVE-2024-1234?"), return the query unchanged.
2. For vague or ambiguous queries, expand them with specific cybersecurity terminology.
3. For follow-up questions with conversation context, resolve ambiguous references.
   - E.g., "Was PowerShell involved?" → "Was PowerShell used in the lateral movement technique from the previous incident?"
4. Do NOT add information that wasn't implied by the query or context.
5. Keep the rewritten query concise — aim for 1-2 sentences max.
6. Output ONLY the rewritten query text, nothing else."""

        context_section = ""
        if conversation_context:
            turns = []
            for turn in conversation_context[-6:]:  # Last 6 turns for context window
                role = turn.get("role", "unknown")
                content = turn.get("content", "")
                turns.append(f"{role}: {content}")
            context_section = "\n\nConversation context:\n" + "\n".join(turns)

        human_prompt = f"Original query: {query}{context_section}"

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]

        response = llm.invoke(messages)
        rewritten = response.content.strip()

        # Safety: if the rewrite is empty or absurdly long, fall back
        if not rewritten or len(rewritten) > len(query) * 5:
            return query

        return rewritten

    except Exception:
        # Rewriting is a nice-to-have — never fail the pipeline over it
        return query


def _is_simple_factual_query(query: str) -> bool:
    """Heuristic: is this query specific enough to not need rewriting?

    Returns True for queries that:
    - Contain CVE identifiers (CVE-YYYY-NNNNN)
    - Contain MITRE technique IDs (TNNNN)
    - Are very short (< 5 words) and look like a lookup
    """
    import re
    query_upper = query.upper().strip()

    # CVE pattern
    if re.search(r'CVE-\d{4}-\d{4,}', query_upper):
        return True

    # MITRE technique pattern
    if re.search(r'\bT\d{4}\b', query_upper):
        return True

    # Very short queries (likely lookups)
    word_count = len(query.split())
    if word_count <= 3:
        return True

    return False
