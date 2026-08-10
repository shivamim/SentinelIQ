"""Alerts router: ingest, correlate, attack replay, parse log files."""

import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import List

from app.database import get_db
from app.models import Alert, CorrelationResult
from app.schemas import (
    AlertIngest,
    AlertOut,
    CorrelationResultOut,
    ParsedAlerts,
)
from app.auth import get_current_user, require_role

from app.graph.builder import build_graph
from app.graph.state import IncidentState

from app.services.langfuse_trace import tracer
from app.services.bm25 import BM25Search
from app.services.neo4j_service import neo4j_service


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)


# ============================================================
# LIST ALERTS
# ============================================================

@router.get(
    "",
    response_model=List[AlertOut],
)
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get all alerts from PostgreSQL.
    """

    result = await db.execute(
        select(Alert).order_by(
            Alert.created_at.desc()
        )
    )

    alerts = result.scalars().all()

    return alerts


# ============================================================
# INGEST ALERT
# ============================================================

@router.post(
    "/ingest",
    response_model=AlertOut,
)
async def ingest_alert(
    payload: AlertIngest,
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
    Ingest a raw SIEM alert.
    """

    alert = Alert(
        source=payload.source,
        raw_alert=payload.raw_alert,
        asset_id=payload.asset_id,
        alert_type=payload.alert_type,
        severity=payload.severity,
        ioc_ip=payload.ioc_ip,
        ioc_domain=payload.ioc_domain,
        ioc_hash=payload.ioc_hash,
        status="new",
    )

    db.add(alert)

    await db.commit()
    await db.refresh(alert)

    # --------------------------------------------------------
    # Update tsvector for BM25
    # --------------------------------------------------------

    search_text = (
        f"{payload.alert_type or ''} "
        f"{payload.severity or ''} "
        f"{payload.source}"
    )

    if isinstance(payload.raw_alert, dict):
        search_text += " " + " ".join(
            str(value)
            for value in payload.raw_alert.values()
            if isinstance(
                value,
                (str, int, float),
            )
        )

    await BM25Search.update_tsvector(
        db,
        "alerts",
        str(alert.id),
        search_text,
    )

    # --------------------------------------------------------
    # Audit log
    # --------------------------------------------------------

    audit_sql = text(
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
    )

    await db.execute(
        audit_sql,
        {
            "actor": str(current_user.id),
            "action": "alert_ingested",
            "entity_type": "alert",
            "entity_id": alert.id,
            "metadata": {
                "source": payload.source,
            },
        },
    )

    await db.commit()

    return alert


# ============================================================
# ATTACK REPLAY — NEO4J WITH SYNC-ON-DEMAND
# ============================================================

@router.get(
    "/{alert_id}/attack-replay",
)
async def get_attack_replay(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return the Neo4j attack graph for an alert.

    The response contains JSON-safe nodes and edges
    suitable for React Flow.

    If the alert node does not exist in Neo4j, this endpoint
    will first synchronize it from PostgreSQL before querying
    the graph.
    """

    try:
        # First, check if the alert exists in PostgreSQL
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail=f"Alert not found: {alert_id}",
            )

        # Check if alert exists in Neo4j
        check_result = await neo4j_service._run(
            "MATCH (a:Alert {id: $alert_id}) RETURN a",
            {"alert_id": alert_id},
        )

        # If alert doesn't exist in Neo4j, sync it from PostgreSQL
        if not check_result:
            sync_result = await neo4j_service.sync_alert_from_postgres(
                db=db,
                alert_id=alert_id,
            )

            if not sync_result.get("success"):
                # Sync failed but alert exists in PostgreSQL
                # Return empty graph with informative message
                return {
                    "alert_id": alert_id,
                    "nodes": [],
                    "edges": [],
                    "message": (
                        "Alert exists in PostgreSQL but could not be "
                        "synchronized to Neo4j. "
                        f"Reason: {sync_result.get('error', 'Unknown error')}"
                    ),
                }

        # Now query the graph
        graph = await neo4j_service.get_attack_replay_graph(
            alert_id=alert_id,
            max_depth=3,
        )

        return graph

    except HTTPException:
        raise

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to load attack replay: {exc}"
            ),
        )


# ============================================================
# CORRELATE ALERT
# ============================================================

@router.post(
    "/{alert_id}/correlate",
)
async def correlate_alert(
    alert_id: str,
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
    Trigger LangGraph correlation for an alert.
    """

    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id
        )
    )

    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # --------------------------------------------------------
    # Initial LangGraph state
    # --------------------------------------------------------

    initial_state: IncidentState = {
        "raw_alert": {
            **alert.raw_alert,
            "id": str(alert.id),
        },

        "asset_context": {},

        "similar_incidents": [],

        "relevant_cves": [],

        "mitre_techniques": [],

        "neo4j_paths": [],

        "reasoning": "",

        "verdict": None,

        "confidence": 0.0,

        "grounding_passed": False,

        "retry_count": 0,

        "severity": None,

        "escalate": False,

        "report": "",
    }

    trace_id = str(uuid.uuid4())

    with tracer.trace_node(
        trace_id,
        "correlate_alert",
        {
            "alert_id": alert_id,
        },
    ):
        graph = build_graph(db)

        config = {
            "configurable": {
                "thread_id": trace_id,
            }
        }

        final_state = await graph.ainvoke(
            initial_state,
            config,
        )

    return {
        "alert_id": alert_id,
        "verdict": final_state.get(
            "verdict"
        ),
        "severity": final_state.get(
            "severity"
        ),
        "confidence": final_state.get(
            "confidence"
        ),
        "grounding_passed": final_state.get(
            "grounding_passed"
        ),
        "report": final_state.get(
            "report"
        ),
        "trace_id": trace_id,
    }


# ============================================================
# GET CORRELATION RESULT
# ============================================================

@router.get(
    "/{alert_id}/correlation",
    response_model=CorrelationResultOut,
)
async def get_correlation(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get the stored correlation result for an alert.
    """

    result = await db.execute(
        select(CorrelationResult).where(
            CorrelationResult.alert_id
            == alert_id
        )
    )

    corr = result.scalar_one_or_none()

    if not corr:
        raise HTTPException(
            status_code=404,
            detail="Correlation result not found",
        )

    return corr


# ============================================================
# PARSE EVTX
# ============================================================

@router.post(
    "/parse/evtx",
    response_model=ParsedAlerts,
)
async def parse_evtx_upload(
    file: UploadFile = File(...),
    current_user=Depends(
        require_role(
            "analyst",
            "senior_analyst",
            "admin",
        )
    ),
):
    """
    Parse an uploaded EVTX file
    into normalized alerts.
    """

    from app.parsers.evtx_parser import (
        parse_evtx_bytes,
    )

    data = await file.read()

    alerts = parse_evtx_bytes(
        data
    )

    return ParsedAlerts(
        source=f"evtx:{file.filename}",
        alerts=alerts,
        parser_type="evtx",
        count=len(alerts),
    )


# ============================================================
# PARSE CSV
# ============================================================

@router.post(
    "/parse/csv",
    response_model=ParsedAlerts,
)
async def parse_csv_upload(
    file: UploadFile = File(...),
    current_user=Depends(
        require_role(
            "analyst",
            "senior_analyst",
            "admin",
        )
    ),
):
    """
    Parse an uploaded CSV file
    into normalized alerts.
    """

    from app.parsers.csv_parser import (
        parse_csv_bytes,
    )

    data = await file.read()

    alerts = parse_csv_bytes(
        data,
        source=f"csv:{file.filename}",
    )

    return ParsedAlerts(
        source=f"csv:{file.filename}",
        alerts=alerts,
        parser_type="csv",
        count=len(alerts),
    )


# ============================================================
# PARSE SYSLOG
# ============================================================

@router.post(
    "/parse/syslog",
    response_model=ParsedAlerts,
)
async def parse_syslog_upload(
    file: UploadFile = File(...),
    current_user=Depends(
        require_role(
            "analyst",
            "senior_analyst",
            "admin",
        )
    ),
):
    """
    Parse an uploaded syslog file
    into normalized alerts.
    """

    from app.parsers.syslog_parser import (
        parse_syslog_stream,
    )

    data = await file.read()

    log_text = data.decode(
        "utf-8",
        errors="replace",
    )

    alerts = parse_syslog_stream(
        log_text,
        source=f"syslog:{file.filename}",
    )

    return ParsedAlerts(
        source=f"syslog:{file.filename}",
        alerts=alerts,
        parser_type="syslog",
        count=len(alerts),
    )
