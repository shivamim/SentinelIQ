"""Review queue router: escalated / uncertain items."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import List

from app.database import get_db
from app.models import Alert, CorrelationResult
from app.schemas import ReviewQueueItem, ReviewResolve
from app.auth import get_current_user, require_role

router = APIRouter(prefix="/review-queue", tags=["review-queue"])


@router.get("", response_model=List[ReviewQueueItem])
async def get_review_queue(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("senior_analyst", "admin")),
):
    """List escalated / uncertain alerts awaiting human review."""
    sql = text("""
        SELECT a.id as alert_id, a.alert_type, a.severity,
               c.verdict, c.confidence_score, c.reasoning_text, c.created_at
        FROM alerts a
        JOIN correlation_results c ON c.alert_id = a.id
        WHERE c.verdict = 'uncertain' OR a.severity IN ('high', 'critical')
        ORDER BY c.created_at DESC
    """)
    result = await db.execute(sql)
    rows = result.mappings().all()
    return [dict(r) for r in rows]


@router.post("/{alert_id}/resolve")
async def resolve_review(
    alert_id: str,
    payload: ReviewResolve,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("senior_analyst", "admin")),
):
    """Analyst confirms/overrides verdict."""
    # Update alert status
    await db.execute(
        text("UPDATE alerts SET status = 'triaged' WHERE id = :id"),
        {"id": alert_id},
    )

    # Update correlation result
    await db.execute(
        text("""
            UPDATE correlation_results
            SET verdict = :verdict,
                reasoning_text = COALESCE(:reasoning, reasoning_text)
            WHERE alert_id = :id
        """),
        {"id": alert_id, "verdict": payload.verdict, "reasoning": payload.reasoning_override},
    )

    # Audit log
    await db.execute(
        text("""
            INSERT INTO audit_log (actor, action, entity_type, entity_id, metadata)
            VALUES (:actor, :action, :entity_type, :entity_id, :metadata)
        """),
        {
            "actor": str(current_user.id),
            "action": "review_resolved",
            "entity_type": "alert",
            "entity_id": alert_id,
            "metadata": {"verdict": payload.verdict, "overridden_by": str(current_user.id)},
        },
    )
    await db.commit()
    return {"status": "resolved", "alert_id": alert_id, "verdict": payload.verdict}
