"""Audit trail router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import List

from app.database import get_db
from app.schemas import AuditLogOut
from app.auth import get_current_user, require_role

router = APIRouter(tags=["audit"])


@router.get("/audit-trail/{entity_id}", response_model=List[AuditLogOut])
async def get_audit_trail(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("senior_analyst", "admin")),
):
    result = await db.execute(
        text("SELECT * FROM audit_log WHERE entity_id = :eid ORDER BY created_at DESC"),
        {"eid": entity_id},
    )
    rows = result.mappings().all()
    return [dict(r) for r in rows]
