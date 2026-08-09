"""Chat router — RAG-powered conversational Q&A with SSE streaming support."""
import uuid
import json
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database import get_db
from app.auth import get_current_user
from app.services.rag_pipeline import RAGPipeline
from app.services.conversation_memory import (
    load_conversation_history,
    save_conversation_turn,
)
from app.models import User

router = APIRouter(prefix="/chat", tags=["chat"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    query: str
    conversation_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None


class SourceCitation(BaseModel):
    document_id: str
    chunk_id: str
    title: str
    source: str
    document_type: str
    score: float
    chunk_text: str


class RetrievalMetrics(BaseModel):
    chunks_retrieved: int
    reranked_count: int
    sources_used: int
    vector_score_range: str
    bm25_score_range: str
    rrf_score_range: str
    reranker: str = "none"
    reranker_status: str = "skipped"


class ChatResponse(BaseModel):
    answer: str
    sources: List[SourceCitation]
    retrieval_metrics: RetrievalMetrics
    grounding_status: str
    conversation_id: str


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Non-streaming RAG chat endpoint.

    Accepts a user query, optional conversation_id, and optional metadata
    filters. Returns a complete answer with sources and metrics.
    Conversation history is loaded from Redis and stored back after the turn.
    """
    if not request.query or not request.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    conversation_id = request.conversation_id or str(uuid.uuid4())

    # Load conversation history from Redis
    conversation_history = await load_conversation_history(conversation_id)

    # Save the user's turn to conversation memory
    await save_conversation_turn(conversation_id, "user", request.query)

    result = await RAGPipeline.search(
        db=db,
        query=request.query,
        conversation_history=conversation_history,
        filters=request.filters,
    )

    # Save the assistant's turn to conversation memory
    await save_conversation_turn(conversation_id, "assistant", result["answer"])

    # Build response with reranker status
    rm = result["retrieval_metrics"]
    retrieval_metrics = RetrievalMetrics(
        chunks_retrieved=rm.get("chunks_retrieved", 0),
        reranked_count=rm.get("reranked_count", 0),
        sources_used=rm.get("sources_used", 0),
        vector_score_range=rm.get("vector_score_range", "N/A"),
        bm25_score_range=rm.get("bm25_score_range", "N/A"),
        rrf_score_range=rm.get("rrf_score_range", "N/A"),
        reranker=rm.get("reranker", "none"),
        reranker_status=rm.get("reranker_status", "skipped"),
    )

    return ChatResponse(
        answer=result["answer"],
        sources=[
            SourceCitation(**s) for s in result["sources"]
        ],
        retrieval_metrics=retrieval_metrics,
        grounding_status=result["grounding_status"],
        conversation_id=conversation_id,
    )


@router.post("/stream")
async def chat_stream(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SSE streaming RAG chat endpoint with REAL LLM token streaming.

    Streams the answer token-by-token using Server-Sent Events.
    Uses Groq's native streaming API — tokens are emitted as generated.
    The final event includes sources, metrics, and grounding status.
    Conversation history is loaded from Redis and stored back after the turn.
    """
    if not request.query or not request.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    conversation_id = request.conversation_id or str(uuid.uuid4())

    async def event_generator():
        """Yield SSE events using real LLM streaming."""
        try:
            # Load conversation history from Redis
            conversation_history = await load_conversation_history(conversation_id)

            # Save the user's turn to conversation memory
            await save_conversation_turn(conversation_id, "user", request.query)

            # Run the streaming RAG pipeline
            full_answer = ""
            final_data = None

            async for event in RAGPipeline.search_stream(
                db=db,
                query=request.query,
                conversation_history=conversation_history,
                filters=request.filters,
            ):
                event_type = event["type"]
                event_data = event["data"]

                if event_type == "status":
                    yield _sse_event("status", event_data)
                elif event_type == "token":
                    yield _sse_event("token", event_data)
                elif event_type == "done":
                    final_data = event_data
                    full_answer = event_data.get("answer", "")

            # Save the assistant's turn to conversation memory
            if full_answer:
                await save_conversation_turn(conversation_id, "assistant", full_answer)

            # Final done event with all metadata
            if final_data:
                yield _sse_event("done", {
                    "answer": final_data.get("answer", ""),
                    "sources": final_data.get("sources", []),
                    "retrieval_metrics": final_data.get("retrieval_metrics", {}),
                    "grounding_status": final_data.get("grounding_status", "unknown"),
                    "conversation_id": conversation_id,
                })
            else:
                yield _sse_event("error", {"message": "No response generated"})

        except Exception as e:
            yield _sse_event("error", {"message": str(e)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse_event(event: str, data: Any) -> str:
    """Format a Server-Sent Event string."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
