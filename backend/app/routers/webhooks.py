"""Webhooks router — live SIEM connector webhooks."""
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Dict, Any

from app.database import get_db
from app.auth import require_role
from app.models import Alert
from app.services.langfuse_trace import tracer

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Known connector schemas
CONNECTOR_SCHEMAS = {
    "splunk": {"alert_field": "result", "severity_field": "severity", "type_field": "search_name"},
    "qradar": {"alert_field": "events", "severity_field": "severity", "type_field": "rule_name"},
    "sentinel": {"alert_field": "alert", "severity_field": "severity", "type_field": "alertType"},
    "wazuh": {"alert_field": "data", "severity_field": "rule.level", "type_field": "rule.description"},
    "generic": {"alert_field": "alert", "severity_field": "severity", "type_field": "alert_type"},
}


@router.post("/siem")
async def siem_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Receive real-time SIEM alerts via webhook.

    Supports unauthenticated push from SIEM tools (validate via
    X-Webhook-Secret header in production).
    """
    payload = await request.json()

    # Extract common fields
    source = payload.get("source", request.headers.get("X-SIEM-Source", "webhook"))
    alert_type = payload.get("alert_type", "webhook_alert")
    severity = payload.get("severity", "medium")
    ioc_ip = payload.get("ioc_ip") or payload.get("src_ip")
    ioc_domain = payload.get("ioc_domain")
    ioc_hash = payload.get("ioc_hash")

    alert = Alert(
        source=source,
        raw_alert=payload,
        alert_type=alert_type,
        severity=severity,
        ioc_ip=ioc_ip,
        ioc_domain=ioc_domain,
        ioc_hash=ioc_hash,
        status="new",
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    # Update tsvector
    from app.services.bm25 import BM25Search
    search_text = f"{alert_type} {severity} {source}"
    await BM25Search.update_tsvector(db, "alerts", str(alert.id), search_text)

    return {"status": "received", "alert_id": str(alert.id)}


@router.post("/connectors/{connector_id}")
async def connector_webhook(
    connector_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Generic connector webhook for Splunk, QRadar, Sentinel, Wazuh, etc.

    The connector_id maps to a known schema that normalizes the payload
    into SentinelIQ alert format.
    """
    payload = await request.json()
    schema = CONNECTOR_SCHEMAS.get(connector_id, CONNECTOR_SCHEMAS["generic"])

    # Normalize based on connector schema
    alert_data = payload.get(schema["alert_field"], payload)
    if isinstance(alert_data, list):
        # Multiple alerts in one payload
        alerts = []
        for item in alert_data:
            alert = _create_alert_from_connector(item, schema, connector_id)
            db.add(alert)
            alerts.append(alert)
        await db.commit()
        return {"status": "received", "count": len(alerts), "alert_ids": [str(a.id) for a in alerts]}
    else:
        alert = _create_alert_from_connector(alert_data, schema, connector_id)
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        return {"status": "received", "alert_id": str(alert.id)}


def _create_alert_from_connector(data: dict, schema: dict, connector_id: str) -> Alert:
    """Create an Alert model from connector-specific data."""
    import json

    alert_type = data.get(schema["type_field"], "connector_alert")

    # Handle nested severity fields (e.g., "rule.level")
    severity = "medium"
    sev_field = schema["severity_field"]
    if "." in sev_field:
        parts = sev_field.split(".")
        val = data
        for part in parts:
            val = val.get(part) if isinstance(val, dict) else None
            if val is None:
                break
        if val is not None:
            severity = str(val)
    else:
        severity = str(data.get(sev_field, "medium"))

    # Normalize severity
    severity = severity.lower()
    if severity not in ("low", "medium", "high", "critical"):
        try:
            level = int(severity)
            if level >= 10:
                severity = "critical"
            elif level >= 7:
                severity = "high"
            elif level >= 4:
                severity = "medium"
            else:
                severity = "low"
        except ValueError:
            severity = "medium"

    ioc_ip = data.get("src_ip") or data.get("source_ip") or data.get("ioc_ip")
    ioc_domain = data.get("ioc_domain") or data.get("dns_query")
    ioc_hash = data.get("ioc_hash") or data.get("file_hash")

    return Alert(
        source=f"connector:{connector_id}",
        raw_alert=data,
        alert_type=alert_type,
        severity=severity,
        ioc_ip=ioc_ip,
        ioc_domain=ioc_domain,
        ioc_hash=ioc_hash,
        status="new",
    )
