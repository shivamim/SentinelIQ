"""Full RAG pipeline: query rewrite → metadata filter → hybrid retrieval → rerank → LLM → grounding → citations.

This module orchestrates the complete retrieval-augmented generation flow
for the document_chunks table, supporting multi-turn conversation and
metadata filtering.
"""
import json
import uuid
import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.services.query_rewriter import rewrite_query
from app.services.embeddings import embedding_service
from app.graph.retrieval import HybridRetrieval, CohereReranker
from app.config import get_settings

settings = get_settings()

# Lazy-init Groq LLM (same pattern as nodes.py)
_llm = None


def _get_llm():
    """Lazy-initialize the Groq ChatGroq instance."""
    global _llm
    if _llm is not None:
        return _llm
    if not settings.GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is required for RAG pipeline LLM generation. "
            "Set the GROQ_API_KEY environment variable."
        )
    from langchain_groq import ChatGroq
    _llm = ChatGroq(
        model=settings.GROQ_MODEL,
        groq_api_key=settings.GROQ_API_KEY,
        temperature=0.1,
        max_tokens=4096,
    )
    return _llm


class RAGPipeline:
    """Complete RAG pipeline:
    query rewrite → metadata filter → hybrid retrieval → rerank → LLM → grounding → citations
    """

    @staticmethod
    async def search(
        db: AsyncSession,
        query: str,
        conversation_history: Optional[List[Dict[str, Any]]] = None,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 20,
        rerank_top_n: int = 5,
    ) -> Dict[str, Any]:
        """Execute the full RAG pipeline (non-streaming).

        Args:
            db: Async SQLAlchemy session.
            query: The user's natural language query.
            conversation_history: Optional list of prior turns (role, content).
            filters: Optional metadata filters. Supported keys:
                - document_type: str or List[str]
                - source: str or List[str]
                - technique_id: str or List[str] (matched in chunk metadata)
                - cve_id: str or List[str] (matched in chunk metadata)
                - severity: str or List[str] (matched in chunk metadata)
                - asset: str (matched in chunk metadata)
                - time_range: dict with 'start' and 'end' ISO timestamps
            top_k: Number of chunks to retrieve from each search method.
            rerank_top_n: Number of results after reranking.

        Returns:
            dict with keys: answer, sources, retrieval_metrics, grounding_status
        """
        # ── Step 1: Rewrite query ──────────────────────────────────────
        rewritten_query = await rewrite_query(query, conversation_history)

        # ── Step 2: Embed the (rewritten) query ────────────────────────
        query_embedding = await asyncio.to_thread(
            embedding_service.embed, [rewritten_query]
        )
        query_embedding = query_embedding[0]

        # ── Step 3: Hybrid retrieval with metadata filtering ───────────
        raw_results = await HybridRetrieval.search_documents(
            db,
            query=rewritten_query,
            query_embedding=query_embedding,
            filters=filters,
            top_k=top_k,
        )

        # ── Step 4: Track retrieval metrics ────────────────────────────
        vector_scores = [r.get("similarity", 0.0) for r in raw_results if "similarity" in r]
        bm25_scores = [r.get("bm25_score", 0.0) for r in raw_results if "bm25_score" in r]
        rrf_scores = [r.get("rrf_score", 0.0) for r in raw_results if "rrf_score" in r]

        metrics: Dict[str, Any] = {
            "chunks_retrieved": len(raw_results),
            "reranked_count": 0,
            "sources_used": 0,
            "vector_score_range": (
                f"{min(vector_scores):.4f}-{max(vector_scores):.4f}"
                if vector_scores else "N/A"
            ),
            "bm25_score_range": (
                f"{min(bm25_scores):.4f}-{max(bm25_scores):.4f}"
                if bm25_scores else "N/A"
            ),
            "rrf_score_range": (
                f"{min(rrf_scores):.4f}-{max(rrf_scores):.4f}"
                if rrf_scores else "N/A"
            ),
            "reranker": "cohere" if settings.COHERE_API_KEY else "none",
            "reranker_status": "skipped",
        }

        # ── Step 4b: Retrieval confidence / abstention check ───────────
        threshold = settings.RETRIEVAL_CONFIDENCE_THRESHOLD
        abstention = False
        if threshold > 0.0:
            # Check if the top result's best score meets the threshold
            top_rrf_score = max(rrf_scores) if rrf_scores else 0.0
            if not raw_results or top_rrf_score < threshold:
                abstention = True

        if abstention:
            # Insufficient retrieval confidence — return evidence-insufficient response
            metrics["sources_used"] = 0
            metrics["reranker_status"] = "skipped"
            return {
                "answer": (
                    "I cannot answer this question with confidence. The retrieved evidence "
                    "does not meet the minimum confidence threshold. Try refining your query "
                    "or adjusting metadata filters."
                ),
                "sources": [],
                "retrieval_metrics": metrics,
                "grounding_status": "evidence_insufficient",
            }

        # ── Step 5: Rerank with Cohere ─────────────────────────────────
        reranked = raw_results
        if settings.COHERE_API_KEY and raw_results:
            reranked, reranker_status = await CohereReranker.rerank_with_status(
                rewritten_query, raw_results, top_n=rerank_top_n
            )
            metrics["reranker_status"] = reranker_status
            metrics["reranked_count"] = len(reranked)
        else:
            metrics["reranker_status"] = "skipped"

        # ── Step 6: Build context from top chunks ──────────────────────
        context_chunks = reranked[:rerank_top_n]
        metrics["sources_used"] = len(context_chunks)

        # If no context chunks available after retrieval, return insufficient evidence
        if not context_chunks:
            return {
                "answer": (
                    "I could not find any relevant documents to answer your question. "
                    "The knowledge base may not contain information on this topic."
                ),
                "sources": [],
                "retrieval_metrics": metrics,
                "grounding_status": "evidence_insufficient",
            }

        context_text = _build_context(context_chunks)

        # ── Step 7: Generate answer with LLM ───────────────────────────
        answer, cited_chunk_ids = await _generate_answer(
            query, rewritten_query, context_text, context_chunks, conversation_history
        )

        # ── Step 8: Verify grounding ───────────────────────────────────
        grounding_status = _verify_grounding(answer, context_chunks, cited_chunk_ids)

        # ── Step 9: Build source citations ─────────────────────────────
        # Only include sources that were actually cited or used
        sources = _build_sources(context_chunks)

        return {
            "answer": answer,
            "sources": sources,
            "retrieval_metrics": metrics,
            "grounding_status": grounding_status,
        }

    @staticmethod
    async def search_stream(
        db: AsyncSession,
        query: str,
        conversation_history: Optional[List[Dict[str, Any]]] = None,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 20,
        rerank_top_n: int = 5,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute the RAG pipeline with real LLM streaming.

        Yields SSE-compatible event dicts:
          - {"type": "status", "data": {...}}  — progress updates
          - {"type": "token", "data": {"text": ...}}  — streamed LLM tokens
          - {"type": "done", "data": {...}}  — final answer + metadata

        This method performs retrieval non-streaming, then streams the LLM
        generation token-by-token using Groq's native streaming API.
        """
        # ── Step 1: Rewrite query ──────────────────────────────────────
        yield {"type": "status", "data": {"message": "Rewriting query..."}}
        rewritten_query = await rewrite_query(query, conversation_history)

        # ── Step 2: Embed the (rewritten) query ────────────────────────
        yield {"type": "status", "data": {"message": "Embedding query..."}}
        query_embedding = await asyncio.to_thread(
            embedding_service.embed, [rewritten_query]
        )
        query_embedding = query_embedding[0]

        # ── Step 3: Hybrid retrieval with metadata filtering ───────────
        yield {"type": "status", "data": {"message": "Searching knowledge base..."}}
        raw_results = await HybridRetrieval.search_documents(
            db,
            query=rewritten_query,
            query_embedding=query_embedding,
            filters=filters,
            top_k=top_k,
        )

        # ── Step 4: Track retrieval metrics ────────────────────────────
        vector_scores = [r.get("similarity", 0.0) for r in raw_results if "similarity" in r]
        bm25_scores = [r.get("bm25_score", 0.0) for r in raw_results if "bm25_score" in r]
        rrf_scores = [r.get("rrf_score", 0.0) for r in raw_results if "rrf_score" in r]

        metrics: Dict[str, Any] = {
            "chunks_retrieved": len(raw_results),
            "reranked_count": 0,
            "sources_used": 0,
            "vector_score_range": (
                f"{min(vector_scores):.4f}-{max(vector_scores):.4f}"
                if vector_scores else "N/A"
            ),
            "bm25_score_range": (
                f"{min(bm25_scores):.4f}-{max(bm25_scores):.4f}"
                if bm25_scores else "N/A"
            ),
            "rrf_score_range": (
                f"{min(rrf_scores):.4f}-{max(rrf_scores):.4f}"
                if rrf_scores else "N/A"
            ),
            "reranker": "cohere" if settings.COHERE_API_KEY else "none",
            "reranker_status": "skipped",
        }

        # ── Step 4b: Retrieval confidence / abstention check ───────────
        threshold = settings.RETRIEVAL_CONFIDENCE_THRESHOLD
        if threshold > 0.0:
            top_rrf_score = max(rrf_scores) if rrf_scores else 0.0
            if not raw_results or top_rrf_score < threshold:
                metrics["sources_used"] = 0
                yield {"type": "done", "data": {
                    "answer": (
                        "I cannot answer this question with confidence. The retrieved evidence "
                        "does not meet the minimum confidence threshold. Try refining your query "
                        "or adjusting metadata filters."
                    ),
                    "sources": [],
                    "retrieval_metrics": metrics,
                    "grounding_status": "evidence_insufficient",
                }}
                return

        # ── Step 5: Rerank with Cohere ─────────────────────────────────
        yield {"type": "status", "data": {"message": "Reranking results..."}}
        reranked = raw_results
        if settings.COHERE_API_KEY and raw_results:
            reranked, reranker_status = await CohereReranker.rerank_with_status(
                rewritten_query, raw_results, top_n=rerank_top_n
            )
            metrics["reranker_status"] = reranker_status
            metrics["reranked_count"] = len(reranked)
        else:
            metrics["reranker_status"] = "skipped"

        # ── Step 6: Build context from top chunks ──────────────────────
        context_chunks = reranked[:rerank_top_n]
        metrics["sources_used"] = len(context_chunks)

        if not context_chunks:
            yield {"type": "done", "data": {
                "answer": (
                    "I could not find any relevant documents to answer your question. "
                    "The knowledge base may not contain information on this topic."
                ),
                "sources": [],
                "retrieval_metrics": metrics,
                "grounding_status": "evidence_insufficient",
            }}
            return

        context_text = _build_context(context_chunks)

        # ── Step 7: Generate answer with LLM (REAL STREAMING) ──────────
        yield {"type": "status", "data": {"message": "Generating answer..."}}

        answer, cited_chunk_ids = "", []
        async for event in _generate_answer_stream(
            query, rewritten_query, context_text, context_chunks, conversation_history
        ):
            if event["type"] == "token":
                answer += event["data"]["text"]
                yield event
            elif event["type"] == "complete":
                answer = event["data"]["answer"]
                cited_chunk_ids = event["data"]["cited_chunk_ids"]

        # ── Step 8: Verify grounding ───────────────────────────────────
        grounding_status = _verify_grounding(answer, context_chunks, cited_chunk_ids)

        # ── Step 9: Build source citations ─────────────────────────────
        sources = _build_sources(context_chunks)

        # ── Final done event ───────────────────────────────────────────
        yield {"type": "done", "data": {
            "answer": answer,
            "sources": sources,
            "retrieval_metrics": metrics,
            "grounding_status": grounding_status,
        }}


def _build_context(chunks: List[Dict[str, Any]]) -> str:
    """Format retrieved chunks into a context string for the LLM."""
    parts = []
    for i, chunk in enumerate(chunks, start=1):
        chunk_text = chunk.get("chunk_text", "")
        doc_title = chunk.get("document_title", "Untitled")
        doc_type = chunk.get("document_type", "unknown")
        chunk_id = chunk.get("id", "unknown")
        parts.append(
            f"[Source {i}, ID: {chunk_id}, Type: {doc_type}, Title: {doc_title}]\n{chunk_text}"
        )
    return "\n\n---\n\n".join(parts)


async def _generate_answer(
    query: str,
    rewritten_query: str,
    context_text: str,
    context_chunks: List[Dict[str, Any]],
    conversation_history: Optional[List[Dict[str, Any]]] = None,
) -> tuple[str, List[str]]:
    """Call the LLM to generate an answer with citations.

    Returns:
        Tuple of (answer_text, list_of_cited_chunk_ids)
    """
    try:
        llm = _get_llm()
        from langchain_core.messages import SystemMessage, HumanMessage

        system_prompt, human_prompt = _build_prompts(
            query, rewritten_query, context_text, conversation_history
        )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]

        response = await asyncio.to_thread(llm.invoke, messages)
        content = response.content.strip()

        answer, cited_ids = _parse_llm_response(content, context_chunks)
        return answer, cited_ids

    except Exception as e:
        return f"Error generating answer: {str(e)}", []


async def _generate_answer_stream(
    query: str,
    rewritten_query: str,
    context_text: str,
    context_chunks: List[Dict[str, Any]],
    conversation_history: Optional[List[Dict[str, Any]]] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Stream the LLM answer token-by-token using Groq's native streaming.

    Yields:
        {"type": "token", "data": {"text": ...}} for each token
        {"type": "complete", "data": {"answer": ..., "cited_chunk_ids": ...}} at the end
    """
    try:
        llm = _get_llm()
        from langchain_core.messages import SystemMessage, HumanMessage

        system_prompt, human_prompt = _build_prompts(
            query, rewritten_query, context_text, conversation_history
        )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]

        # Use Groq's native streaming via LangChain
        collected_content = ""
        try:
            # llm.stream() is an async generator in langchain-groq
            stream = llm.stream(messages)
            # langchain-groq stream may be sync or async — handle both
            if hasattr(stream, '__aiter__'):
                async for chunk in stream:
                    token = chunk.content
                    if token:
                        collected_content += token
                        yield {"type": "token", "data": {"text": token}}
            else:
                # Sync iterator — run in thread
                def _consume_sync_stream():
                    tokens = []
                    for chunk in stream:
                        if chunk.content:
                            tokens.append(chunk.content)
                    return tokens

                tokens = await asyncio.to_thread(_consume_sync_stream)
                for token in tokens:
                    collected_content += token
                    yield {"type": "token", "data": {"text": token}}
        except (AttributeError, TypeError):
            # Fallback: if streaming not available, invoke and yield as single chunk
            response = await asyncio.to_thread(llm.invoke, messages)
            collected_content = response.content.strip()
            yield {"type": "token", "data": {"text": collected_content}}

        # Parse the complete response for citations
        answer, cited_ids = _parse_llm_response(collected_content.strip(), context_chunks)

        yield {"type": "complete", "data": {
            "answer": answer,
            "cited_chunk_ids": cited_ids,
        }}

    except Exception as e:
        error_msg = f"Error generating answer: {str(e)}"
        yield {"type": "complete", "data": {
            "answer": error_msg,
            "cited_chunk_ids": [],
        }}


def _build_prompts(
    query: str,
    rewritten_query: str,
    context_text: str,
    conversation_history: Optional[List[Dict[str, Any]]] = None,
) -> tuple[str, str]:
    """Build system and human prompts for the LLM."""
    system_prompt = """You are a cybersecurity incident analysis assistant. Answer the user's question based ONLY on the provided source context.

Rules:
1. Answer the question using information from the provided sources.
2. Cite sources by referencing their Source number, e.g., "According to [Source 1]..."
3. If the sources don't contain enough information to fully answer, say so explicitly.
4. Do NOT fabricate or hallucinate information not present in the sources.
5. Be specific and include relevant IDs (CVE IDs, technique IDs, incident IDs) from the sources.
6. Structure your answer clearly with bullet points or sections when appropriate.

Output your answer in the following JSON format:
{
  "answer": "your answer text here with [Source N] citations",
  "cited_source_ids": ["id1", "id2", ...]
}"""

    # Include conversation history for context if present
    history_section = ""
    if conversation_history:
        turns = []
        for turn in conversation_history[-4:]:
            role = turn.get("role", "unknown")
            content = turn.get("content", "")
            turns.append(f"{role}: {content}")
        history_section = "\n\nPrevious conversation:\n" + "\n".join(turns)

    human_prompt = f"""Question: {query}

(Rewritten for retrieval: {rewritten_query})
{history_section}

Source Context:
{context_text}"""

    return system_prompt, human_prompt


def _parse_llm_response(
    content: str,
    context_chunks: List[Dict[str, Any]],
) -> tuple[str, List[str]]:
    """Parse the LLM response to extract answer and cited chunk IDs.

    Returns:
        Tuple of (answer_text, list_of_cited_chunk_ids)
    """
    try:
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        parsed = json.loads(content)
        answer = parsed.get("answer", content)
        cited_ids = parsed.get("cited_source_ids", [])
        return answer, cited_ids
    except (json.JSONDecodeError, IndexError):
        # If LLM didn't return valid JSON, use raw content as answer
        answer = content
        # Try to extract source IDs from the answer text
        cited_ids = []
        for chunk in context_chunks:
            chunk_id = str(chunk.get("id", ""))
            if chunk_id and chunk_id in answer:
                cited_ids.append(chunk_id)
        return answer, cited_ids


def _verify_grounding(
    answer: str,
    context_chunks: List[Dict[str, Any]],
    cited_chunk_ids: List[str],
) -> str:
    """Verify that the answer is grounded in the retrieved context.

    Checks that cited source IDs correspond to actual retrieved chunks.
    Never reports a source that was not actually retrieved.

    Returns:
        One of: "fully_grounded", "partially_grounded", "ungrounded", "evidence_insufficient"
    """
    if not answer:
        return "evidence_insufficient"

    # If the answer explicitly indicates insufficient evidence, trust it
    insufficient_phrases = [
        "does not contain enough information",
        "do not contain enough information",
        "could not find",
        "cannot answer",
        "can't answer",
        "insufficient evidence",
        "not enough information",
        "no relevant documents",
        "no relevant information",
        "unable to answer",
    ]
    answer_lower = answer.lower()
    if any(phrase in answer_lower for phrase in insufficient_phrases):
        return "evidence_insufficient"

    valid_chunk_ids = {str(c.get("id", "")) for c in context_chunks}
    cited_ids_set = set(str(cid) for cid in cited_chunk_ids if cid)

    if not cited_ids_set:
        # No explicit citations — check if answer mentions source numbers
        # This is a weaker grounding check
        if any(f"[Source {i}]" in answer for i in range(1, len(context_chunks) + 1)):
            return "partially_grounded"
        return "ungrounded"

    # Check what fraction of cited IDs are in the valid set
    # Filter out any fabricated IDs — only keep IDs that are actually in retrieved set
    valid_citations = cited_ids_set & valid_chunk_ids
    fabricated = cited_ids_set - valid_chunk_ids

    # If there are fabricated citations, the answer is at best partially grounded
    if fabricated:
        if valid_citations:
            return "partially_grounded"
        else:
            return "ungrounded"

    if len(valid_citations) == len(cited_ids_set):
        return "fully_grounded"
    elif len(valid_citations) > 0:
        return "partially_grounded"
    else:
        return "ungrounded"


def _build_sources(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build source citation dicts from retrieved chunks.

    Only includes chunks that were actually retrieved — never fabricates citations.
    """
    sources = []
    for chunk in chunks:
        chunk_text = chunk.get("chunk_text", "")
        # Truncate preview to 200 chars
        preview = chunk_text[:200] + "..." if len(chunk_text) > 200 else chunk_text

        sources.append({
            "document_id": str(chunk.get("document_id", "")),
            "chunk_id": str(chunk.get("id", "")),
            "title": chunk.get("document_title", "Untitled"),
            "source": chunk.get("document_source", "unknown"),
            "document_type": chunk.get("document_type", "unknown"),
            "score": chunk.get("rrf_score", chunk.get("rerank_score", chunk.get("similarity", 0.0))),
            "chunk_text": preview,
        })
    return sources
