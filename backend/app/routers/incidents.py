"""Incidents router: list, get, add postmortem."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import List

from app.database import get_db
from app.models import Incident, Postmortem, PostmortemEmbedding
from app.schemas import IncidentCreate, IncidentOut, PostmortemCreate, PostmortemOut
from app.auth import get_current_user, require_role
from app.services.embeddings import embedding_service
from app.services.bm25 import BM25Search

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=List[IncidentOut])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Incident).order_by(Incident.opened_at.desc()))
    return result.scalars().all()


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/{incident_id}/postmortem", response_model=PostmortemOut)
async def add_postmortem(
    incident_id: str,
    payload: PostmortemCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("senior_analyst", "admin")),
):
    """Add postmortem and auto-embed into pgvector."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    pm = Postmortem(
        incident_id=incident_id,
        summary=payload.summary,
        root_cause=payload.root_cause,
        remediation=payload.remediation,
        tags=payload.tags or [],
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    # Auto-embed
    chunk = f"Summary: {payload.summary}\nRoot Cause: {payload.root_cause or 'N/A'}\nRemediation: {payload.remediation or 'N/A'}"
    emb = embedding_service.embed([chunk])[0]

    emb_sql = text("""
        INSERT INTO postmortem_embeddings (postmortem_id, chunk_text, embedding)
        VALUES (:pid, :chunk, :embedding)
    """)
    await db.execute(emb_sql, {
        "pid": str(pm.id),
        "chunk": chunk,
        "embedding": str(emb),
    })
    await db.commit()

    # Update tsvector for BM25 search
    search_text = f"{payload.summary} {payload.root_cause or ''} {payload.remediation or ''}"
    await BM25Search.update_tsvector(db, "postmortems", str(pm.id), search_text)

    return pm
