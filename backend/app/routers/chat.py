"""Chat router — RAG-powered conversational Q&A with SSE streaming support."""

import uuid
import json
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field, model_validator

from app.database import get_db
from app.auth import get_current_user
from app.services.rag_pipeline import RAGPipeline
from app.services.conversation_memory import (
    load_conversation_history,
    save_conversation_turn,
)
from app.models import User


router = APIRouter(prefix="/chat", tags=["chat"])


# ============================================================
# Schemas
# ============================================================

class ChatRequest(BaseModel):
    """
    Chat request.

    Supports both:
        {"query": "..."}
    and:
        {"question": "..."}

    This keeps the API backward compatible with older frontend code.
    """

    query: Optional[str] = None
    question: Optional[str] = None

    conversation_id: Optional[str] = None

    filters: Optional[Dict[str, Any]] = None

    # Frontend currently sends document_type directly.
    document_type: Optional[str] = None

    @model_validator(mode="after")
    def normalize_query(self):
        """
        Accept either `query` or `question`.

        `query` takes precedence if both are supplied.
        """

        if not self.query and self.question:
            self.query = self.question

        if not self.query or not self.query.strip():
            raise ValueError("Either 'query' or 'question' must be provided")

        self.query = self.query.strip()

        return self

    def get_filters(self) -> Optional[Dict[str, Any]]:
        """
        Normalize frontend/backend filter formats.

        Backend format:
            filters={"document_type": "mitre_attack"}

        Frontend format:
            document_type="mitre_attack"
        """

        normalized = dict(self.filters or {})

        if self.document_type:
            normalized["document_type"] = self.document_type

        return normalized or None


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


# ============================================================
# Helpers
# ============================================================

def build_retrieval_metrics(result: Dict[str, Any]) -> RetrievalMetrics:
    """
    Safely convert RAG pipeline metrics into the API response schema.
    """

    rm = result.get("retrieval_metrics") or {}

    return RetrievalMetrics(
        chunks_retrieved=rm.get("chunks_retrieved", 0),
        reranked_count=rm.get("reranked_count", 0),
        sources_used=rm.get("sources_used", 0),
        vector_score_range=rm.get("vector_score_range", "N/A"),
        bm25_score_range=rm.get("bm25_score_range", "N/A"),
        rrf_score_range=rm.get("rrf_score_range", "N/A"),
        reranker=rm.get("reranker", "none"),
        reranker_status=rm.get("reranker_status", "skipped"),
    )


def build_sources(result: Dict[str, Any]) -> List[SourceCitation]:
    """
    Safely convert RAG source dictionaries into Pydantic models.
    """

    sources = result.get("sources") or []

    output = []

    for source in sources:
        try:
            output.append(
                SourceCitation(
                    document_id=str(source.get("document_id", "")),
                    chunk_id=str(source.get("chunk_id", "")),
                    title=str(source.get("title", "")),
                    source=str(source.get("source", "")),
                    document_type=str(source.get("document_type", "")),
                    score=float(source.get("score", 0.0)),
                    chunk_text=str(source.get("chunk_text", "")),
                )
            )
        except Exception:
            # Do not allow one malformed citation to break the entire chat.
            continue

    return output


def _sse_event(event: str, data: Any) -> str:
    """
    Format a Server-Sent Event.
    """

    return (
        f"event: {event}\n"
        f"data: {json.dumps(data, default=str)}\n\n"
    )


# ============================================================
# Non-streaming Chat
# ============================================================

@router.post("/", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Non-streaming RAG chat endpoint.

    Accepts:

        {
            "query": "...",
            "conversation_id": "...",
            "filters": {
                "document_type": "mitre_attack"
            }
        }

    Also accepts the frontend-compatible format:

        {
            "question": "...",
            "conversation_id": "...",
            "document_type": "mitre_attack"
        }
    """

    query = request.query.strip()

    if not query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    conversation_id = request.conversation_id or str(uuid.uuid4())

    filters = request.get_filters()

    try:
        # ----------------------------------------------------
        # Load previous conversation
        # ----------------------------------------------------

        conversation_history = await load_conversation_history(
            conversation_id
        )

        # ----------------------------------------------------
        # Save user message
        # ----------------------------------------------------

        await save_conversation_turn(
            conversation_id,
            "user",
            query,
        )

        # ----------------------------------------------------
        # Run RAG
        # ----------------------------------------------------

        result = await RAGPipeline.search(
            db=db,
            query=query,
            conversation_history=conversation_history,
            filters=filters,
        )

        # ----------------------------------------------------
        # Save assistant response
        # ----------------------------------------------------

        answer = result.get("answer", "")

        if answer:
            await save_conversation_turn(
                conversation_id,
                "assistant",
                answer,
            )

        # ----------------------------------------------------
        # Build response
        # ----------------------------------------------------

        retrieval_metrics = build_retrieval_metrics(result)

        sources = build_sources(result)

        return ChatResponse(
            answer=answer,
            sources=sources,
            retrieval_metrics=retrieval_metrics,
            grounding_status=result.get(
                "grounding_status",
                "unknown",
            ),
            conversation_id=conversation_id,
        )

    except HTTPException:
        raise

    except Exception as e:
        print(
            f"[CHAT ERROR] conversation_id={conversation_id}: {e}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat request failed: {str(e)}",
        )


# ============================================================
# Streaming Chat
# ============================================================

@router.post("/stream")
async def chat_stream(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    SSE streaming RAG chat endpoint.

    Supports both:

        {
            "query": "..."
        }

    and:

        {
            "question": "..."
        }

    The response is streamed as:

        event: status
        data: {...}

        event: token
        data: {...}

        event: done
        data: {...}
    """

    query = request.query.strip()

    if not query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    conversation_id = request.conversation_id or str(uuid.uuid4())

    filters = request.get_filters()

    async def event_generator():
        """
        Generate SSE events from the streaming RAG pipeline.
        """

        try:
            # ------------------------------------------------
            # Load conversation history
            # ------------------------------------------------

            conversation_history = await load_conversation_history(
                conversation_id
            )

            # ------------------------------------------------
            # Save user message
            # ------------------------------------------------

            await save_conversation_turn(
                conversation_id,
                "user",
                query,
            )

            # ------------------------------------------------
            # Notify frontend
            # ------------------------------------------------

            yield _sse_event(
                "status",
                {
                    "message": "Searching knowledge base..."
                },
            )

            # ------------------------------------------------
            # Run streaming RAG pipeline
            # ------------------------------------------------

            full_answer = ""
            final_data = None

            async for event in RAGPipeline.search_stream(
                db=db,
                query=query,
                conversation_history=conversation_history,
                filters=filters,
            ):

                if not event:
                    continue

                event_type = event.get("type")
                event_data = event.get("data")

                # --------------------------------------------
                # Status
                # --------------------------------------------

                if event_type == "status":

                    if isinstance(event_data, dict):
                        yield _sse_event(
                            "status",
                            event_data,
                        )
                    else:
                        yield _sse_event(
                            "status",
                            {
                                "message": str(event_data)
                            },
                        )

                # --------------------------------------------
                # Token
                # --------------------------------------------

                elif event_type == "token":

                    # RAG pipeline may return either:
                    #
                    # {"text": "..."}
                    #
                    # or simply:
                    #
                    # "..."

                    if isinstance(event_data, dict):
                        token_text = str(
                            event_data.get(
                                "text",
                                event_data.get(
                                    "token",
                                    "",
                                ),
                            )
                        )
                    else:
                        token_text = str(
                            event_data or ""
                        )

                    full_answer += token_text

                    yield _sse_event(
                        "token",
                        {
                            "text": token_text
                        },
                    )

                # --------------------------------------------
                # Final result
                # --------------------------------------------

                elif event_type == "done":

                    if isinstance(event_data, dict):
                        final_data = event_data

                        full_answer = event_data.get(
                            "answer",
                            full_answer,
                        )

                # --------------------------------------------
                # Pipeline error
                # --------------------------------------------

                elif event_type == "error":

                    if isinstance(event_data, dict):
                        message = event_data.get(
                            "message",
                            "RAG pipeline error",
                        )
                    else:
                        message = str(event_data)

                    yield _sse_event(
                        "error",
                        {
                            "message": message
                        },
                    )

                    return

            # ------------------------------------------------
            # Save assistant response
            # ------------------------------------------------

            if full_answer:
                await save_conversation_turn(
                    conversation_id,
                    "assistant",
                    full_answer,
                )

            # ------------------------------------------------
            # Build final response
            # ------------------------------------------------

            if final_data is None:
                final_data = {}

            final_answer = final_data.get(
                "answer",
                full_answer,
            )

            final_sources = final_data.get(
                "sources",
                [],
            )

            final_metrics = final_data.get(
                "retrieval_metrics",
                {},
            )

            final_grounding = final_data.get(
                "grounding_status",
                "unknown",
            )

            # ------------------------------------------------
            # Send final done event
            # ------------------------------------------------

            yield _sse_event(
                "done",
                {
                    "answer": final_answer,
                    "sources": final_sources,
                    "retrieval_metrics": final_metrics,
                    "grounding_status": final_grounding,
                    "conversation_id": conversation_id,
                },
            )

        except Exception as e:

            print(
                f"[CHAT STREAM ERROR] "
                f"conversation_id={conversation_id}: {e}"
            )

            yield _sse_event(
                "error",
                {
                    "message": str(e)
                },
            )

    # ========================================================
    # Streaming response
    # ========================================================

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
