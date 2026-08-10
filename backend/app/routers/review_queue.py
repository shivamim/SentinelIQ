"""Review queue router: alerts requiring human review."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, CorrelationResult, AuditLog
from app.schemas import ReviewQueueItem, ReviewResolve
from app.auth import get_current_user, require_role


router = APIRouter(
    prefix="/review-queue",
    tags=["review-queue"],
)


# ============================================================
# GET REVIEW QUEUE
# ============================================================

@router.get("", response_model=List[ReviewQueueItem])
async def get_review_queue(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return alerts that require human review.

    Includes:
    - high severity alerts
    - critical severity alerts
    - uncertain correlation results

    Alerts without a correlation result are also included.
    """

    sql = text(
        """
        SELECT
            a.id AS alert_id,
            a.alert_type,
            a.severity,

            COALESCE(
                c.verdict,
                'uncertain'
            ) AS verdict,

            c.confidence_score,

            COALESCE(
                c.reasoning_text,
                'Awaiting correlation analysis and analyst review.'
            ) AS reasoning_text,

            COALESCE(
                c.created_at,
                a.created_at
            ) AS created_at

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

            COALESCE(
                c.created_at,
                a.created_at
            ) DESC
        """
    )

    result = await db.execute(sql)

    rows = result.mappings().all()

    return [dict(row) for row in rows]


# ============================================================
# RESOLVE REVIEW ITEM
# ============================================================

@router.post("/{alert_id}/resolve")
async def resolve_review(
    alert_id: str,
    payload: ReviewResolve,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(
        require_role(
            "analyst",
            "senior_analyst",
            "admin",
        )
    ),
):
    """
    Resolve an alert from the review queue.

    Possible verdicts:

    - known_pattern
    - novel
    - uncertain

    The alert is marked as triaged and the analyst
    decision is persisted.
    """

    # --------------------------------------------------------
    # 1. Find alert
    # --------------------------------------------------------

    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id
        )
    )

    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # --------------------------------------------------------
    # 2. Find latest correlation result
    # --------------------------------------------------------

    result = await db.execute(
        select(CorrelationResult)
        .where(
            CorrelationResult.alert_id == alert_id
        )
        .order_by(
            CorrelationResult.created_at.desc()
        )
    )

    correlation = result.scalars().first()

    # --------------------------------------------------------
    # 3. Update existing correlation result
    # --------------------------------------------------------

    if correlation is not None:

        correlation.verdict = payload.verdict

        if payload.reasoning_override:
            correlation.reasoning_text = (
                payload.reasoning_override
            )

        # Human review means the result has been grounded
        # through analyst validation.
        correlation.grounding_passed = True

        await db.flush()

    # --------------------------------------------------------
    # 4. Create correlation result if none exists
    # --------------------------------------------------------

    else:

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

    # --------------------------------------------------------
    # 5. Mark alert as triaged
    # --------------------------------------------------------

    alert.status = "triaged"

    await db.flush()

    # --------------------------------------------------------
    # 6. Create audit log
    #
    # IMPORTANT:
    # Use SQLAlchemy ORM here instead of raw text().
    #
    # The AuditLog.metadata_json field is a JSON column,
    # so SQLAlchemy correctly serializes the Python dict.
    # --------------------------------------------------------

    audit_log = AuditLog(
        actor=str(current_user.id),

        action="review_resolved",

        entity_type="alert",

        entity_id=alert.id,

        metadata_json={
            "verdict": payload.verdict,
            "resolved_by": str(current_user.id),
        },
    )

    db.add(audit_log)

    # --------------------------------------------------------
    # 7. Commit everything atomically
    # --------------------------------------------------------

    try:
        await db.commit()

    except Exception:
        await db.rollback()
        raise

    # --------------------------------------------------------
    # 8. Return result
    # --------------------------------------------------------

    return {
        "status": "resolved",
        "alert_id": str(alert.id),
        "verdict": payload.verdict,
    }
