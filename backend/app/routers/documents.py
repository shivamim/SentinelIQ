"""Documents router — document ingestion, listing, and retrieval with auto-chunking & embedding."""
import asyncio
import json
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, func
from pydantic import BaseModel, Field
from uuid import UUID

from app.database import get_db
from app.auth import get_current_user, require_role
from app.models import Document, DocumentChunk, User
from app.services.chunking import chunk_document
from app.services.embeddings import embedding_service

router = APIRouter(prefix="/documents", tags=["documents"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class DocumentIngest(BaseModel):
    title: str
    source: str
    source_url: Optional[str] = None
    document_type: str  # mitre_attack, cve, incident, postmortem, markdown, json
    content: str
    metadata_json: Optional[Dict[str, Any]] = None


class DocumentChunkOut(BaseModel):
    id: UUID
    document_id: UUID
    chunk_index: int
    chunk_text: str
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DocumentOut(BaseModel):
    id: UUID
    title: str
    source: str
    source_url: Optional[str]
    document_type: str
    content: str
    metadata_json: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: Optional[datetime]
    chunks: Optional[List[DocumentChunkOut]] = None

    class Config:
        from_attributes = True


class DocumentListItem(BaseModel):
    """Lightweight document list item without content/chunks."""
    id: UUID
    title: str
    source: str
    source_url: Optional[str]
    document_type: str
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class IngestResponse(BaseModel):
    document_id: UUID
    title: str
    document_type: str
    chunk_count: int


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/ingest", response_model=IngestResponse)
async def ingest_document(
    doc: DocumentIngest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "senior_analyst", "admin")),
):
    """Ingest a document: create record, chunk, embed, and store.

    1. Create a Document record.
    2. Chunk the document using the chunking service.
    3. Embed all chunks using Voyage AI.
    4. Insert DocumentChunk records with embeddings.
    5. Return document info + chunk count.
    """
    if not doc.content or not doc.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document content cannot be empty",
        )

    valid_types = {"mitre_attack", "cve", "incident", "postmortem", "markdown", "json"}
    if doc.document_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid document_type. Must be one of: {valid_types}",
        )

    # 1. Create Document record
    document = Document(
        title=doc.title,
        source=doc.source,
        source_url=doc.source_url,
        document_type=doc.document_type,
        content=doc.content,
        metadata_json=doc.metadata_json or {},
    )
    db.add(document)
    await db.commit()
    await db.refresh(document)

    # 2. Chunk the document
    chunk_metadata = {
        "document_id": str(document.id),
        "document_type": doc.document_type,
        "source": doc.source,
        "title": doc.title,
    }
    # Propagate specific IDs from document metadata
    if doc.metadata_json:
        for key in ("technique_id", "cve_id", "incident_id", "severity", "asset"):
            if key in doc.metadata_json:
                chunk_metadata[key] = doc.metadata_json[key]

    chunks = chunk_document(
        content=doc.content,
        metadata=chunk_metadata,
    )

    if not chunks:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Chunking produced zero chunks — document may be too short",
        )

    # 3. Embed all chunk texts
    chunk_texts = [c["chunk_text"] for c in chunks]
    try:
        embeddings = await asyncio.to_thread(embedding_service.embed, chunk_texts)
    except RuntimeError as e:
        # If embedding fails, clean up the document record
        await db.delete(document)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Embedding failed: {str(e)}",
        )

    # 4. Insert DocumentChunk records with embeddings
    # Use raw SQL for pgvector compatibility
    for chunk_data, embedding in zip(chunks, embeddings):
        chunk_sql = text("""
            INSERT INTO document_chunks
            (id, document_id, chunk_index, chunk_text, embedding, metadata, created_at)
            VALUES (:id, :doc_id, :chunk_idx, :chunk_text, :embedding, :metadata, now())
        """)
        await db.execute(chunk_sql, {
            "id": str(uuid.uuid4()),
            "doc_id": str(document.id),
            "chunk_idx": chunk_data["chunk_index"],
            "chunk_text": chunk_data["chunk_text"],
            "embedding": str(embedding),
            "metadata": json.dumps(chunk_data["metadata"]) if chunk_data.get("metadata") else None,
        })

    await db.commit()

    return IngestResponse(
        document_id=document.id,
        title=document.title,
        document_type=document.document_type,
        chunk_count=len(chunks),
    )


@router.get("/", response_model=List[DocumentListItem])
async def list_documents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    document_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all documents with pagination, optionally filtered by type."""
    query = select(Document).order_by(Document.created_at.desc()).offset(skip).limit(limit)

    if document_type:
        query = query.where(Document.document_type == document_type)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{document_id}", response_model=DocumentOut)
async def get_document(
    document_id: UUID,
    include_chunks: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a document by ID, optionally including its chunks."""
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Build response
    doc_out = DocumentOut(
        id=document.id,
        title=document.title,
        source=document.source,
        source_url=document.source_url,
        document_type=document.document_type,
        content=document.content,
        metadata_json=document.metadata_json,
        created_at=document.created_at,
        updated_at=document.updated_at,
    )

    if include_chunks:
        chunk_result = await db.execute(
            select(DocumentChunk)
            .where(DocumentChunk.document_id == document_id)
            .order_by(DocumentChunk.chunk_index)
        )
        chunks = chunk_result.scalars().all()
        doc_out.chunks = [
            DocumentChunkOut(
                id=c.id,
                document_id=c.document_id,
                chunk_index=c.chunk_index,
                chunk_text=c.chunk_text,
                metadata_json=c.metadata_json,
                created_at=c.created_at,
            )
            for c in chunks
        ]

    return doc_out
