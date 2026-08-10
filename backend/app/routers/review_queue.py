"""Review queue router: alerts requiring human review."""

from fastapi import APIRouter, Depends, HTTPException
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
    current_user=Depends(get_current_user),
):
    """
    Return alerts that require human review.

    High/critical alerts are included even when they do not yet
    have a correlation result.
    """

    sql = text(
        """
        SELECT
            a.id AS alert_id,
            a.alert_type,
            a.severity,
            COALESCE(c.verdict, 'uncertain') AS verdict,
            c.confidence_score,
            COALESCE(
                c.reasoning_text,
                'Awaiting correlation analysis and analyst review.'
            ) AS reasoning_text,
            COALESCE(c.created_at, a.created_at) AS created_at
        FROM alerts a
        LEFT JOIN LATERAL (
            SELECT
                cr.verdict,
                cr.confidence_score,
                cr.reasoning_text,
                cr.created_at
            FROM correlation_results cr
            WHERE cr.alert_id = a.id
            ORDER BY cr.created_at DESC
            LIMIT 1
        ) c ON TRUE
        WHERE
            a.status IS DISTINCT FROM 'triaged'
            AND (
                a.severity IN ('high', 'critical')
                OR c.verdict = 'uncertain'
            )
        ORDER BY
            CASE
                WHEN a.severity = 'critical' THEN 1
                WHEN a.severity = 'high' THEN 2
                WHEN a.severity = 'medium' THEN 3
                ELSE 4
            END,
            COALESCE(c.created_at, a.created_at) DESC
        """
    )

    result = await db.execute(sql)
    rows = result.mappings().all()

    return [dict(row) for row in rows]


@router.post("/{alert_id}/resolve")
async def resolve_review(
    alert_id: str,
    payload: ReviewResolve,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(
        require_role("analyst", "senior_analyst", "admin")
    ),
):
    """
    Resolve a review queue item.

    The alert is marked as triaged and the latest correlation
    result is updated. If no correlation result exists, one is created.
    """

    # ---------------------------------------------------------
    # Verify alert exists
    # ---------------------------------------------------------

    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )

    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # ---------------------------------------------------------
    # Mark alert as triaged
    # ---------------------------------------------------------

    await db.execute(
        text(
            """
            UPDATE alerts
            SET status = 'triaged'
            WHERE id = :id
            """
        ),
        {"id": alert_id},
    )

    # ---------------------------------------------------------
    # Find existing correlation result
    # ---------------------------------------------------------

    result = await db.execute(
        select(CorrelationResult)
        .where(CorrelationResult.alert_id == alert_id)
        .order_by(CorrelationResult.created_at.desc())
    )

    correlation = result.scalars().first()

    if correlation:

        correlation.verdict = payload.verdict

        if payload.reasoning_override:
            correlation.reasoning_text = payload.reasoning_override

        await db.flush()

    else:
        # -----------------------------------------------------
        # No correlation result exists yet.
        # Create one so the analyst decision is persisted.
        # -----------------------------------------------------

        correlation = CorrelationResult(
            alert_id=alert.id,
            matched_incident_ids=[],
            matched_cve_ids=[],
            matched_mitre_techniques=[],
            reasoning_text=(
                payload.reasoning_override
                or "Verdict assigned manually by analyst."
            ),
            confidence_score=1.0,
            verdict=payload.verdict,
            grounding_passed=True,
            retry_count=0,
        )

        db.add(correlation)

        await db.flush()

    # ---------------------------------------------------------
    # Audit log
    # ---------------------------------------------------------

    await db.execute(
        text(
            """
            INSERT INTO audit_log
            (
                actor,
                action,
                entity_type,
                entity_id,
                metadata
            )
            VALUES
            (
                :actor,
                :action,
                :entity_type,
                :entity_id,
                :metadata
            )
            """
        ),
        {
            "actor": str(current_user.id),
            "action": "review_resolved",
            "entity_type": "alert",
            "entity_id": alert_id,
            "metadata": {
                "verdict": payload.verdict,
                "resolved_by": str(current_user.id),
            },
        },
    )

    await db.commit()

    return {
        "status": "resolved",
        "alert_id": alert_id,
        "verdict": payload.verdict,
    }
