"""Reports router — PDF incident report generation."""
import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import Optional

from app.database import get_db
from app.models import Incident, CorrelationResult, Postmortem, Alert
from app.auth import get_current_user, require_role

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/incidents/{incident_id}/pdf")
async def generate_incident_report(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst", "senior_analyst", "admin")),
):
    """Generate a PDF incident report using ReportLab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    # Fetch incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch postmortem
    pm_result = await db.execute(
        select(Postmortem).where(Postmortem.incident_id == incident_id)
    )
    postmortem = pm_result.scalar_one_or_none()

    # Fetch correlation results for linked alerts
    corr_result = await db.execute(
        text("""
            SELECT c.verdict, c.confidence_score, c.reasoning_text, c.grounding_passed,
                   a.alert_type, a.severity as alert_severity, a.source
            FROM correlation_results c
            JOIN alerts a ON a.id = c.alert_id
            WHERE a.raw_alert::text LIKE :incident_ref
            ORDER BY c.created_at DESC
            LIMIT 10
        """),
        {"incident_ref": f"%{incident_id}%"},
    )
    correlations = [dict(r) for r in corr_result.mappings().all()]

    # Build PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=18,
        spaceAfter=30,
        textColor=colors.HexColor('#1a1a2e'),
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#16213e'),
    )

    elements = []

    # Title
    elements.append(Paragraph(f"SentinelIQ Incident Report", title_style))
    elements.append(Spacer(1, 20))

    # Incident details table
    incident_data = [
        ["Field", "Value"],
        ["Incident ID", str(incident.id)],
        ["Title", incident.title or "N/A"],
        ["Description", incident.description or "N/A"],
        ["Severity", incident.severity or "N/A"],
        ["Status", incident.status or "N/A"],
        ["Opened", str(incident.opened_at) if incident.opened_at else "N/A"],
        ["Closed", str(incident.closed_at) if incident.closed_at else "Open"],
    ]
    table = Table(incident_data, colWidths=[2*inch, 4.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    # Postmortem section
    if postmortem:
        elements.append(Paragraph("Postmortem", heading_style))
        elements.append(Paragraph(f"<b>Summary:</b> {postmortem.summary}", styles['Normal']))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Root Cause:</b> {postmortem.root_cause or 'N/A'}", styles['Normal']))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Remediation:</b> {postmortem.remediation or 'N/A'}", styles['Normal']))
        elements.append(Spacer(1, 20))

    # Correlation results
    if correlations:
        elements.append(Paragraph("Correlation Results", heading_style))
        corr_data = [["Alert Type", "Severity", "Verdict", "Confidence", "Grounding"]]
        for c in correlations:
            corr_data.append([
                c.get("alert_type", "N/A"),
                c.get("alert_severity", "N/A"),
                c.get("verdict", "N/A"),
                f"{c.get('confidence_score', 0):.2f}" if c.get("confidence_score") else "N/A",
                "Yes" if c.get("grounding_passed") else "No",
            ])
        corr_table = Table(corr_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 1*inch, 1*inch])
        corr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(corr_table)

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"},
    )


@router.get("/dashboard")
async def get_dashboard_data(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get dashboard summary data."""
    # Alert counts by severity
    severity_result = await db.execute(text("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """))
    severity_counts = {r["severity"]: r["count"] for r in severity_result.mappings().all()}

    # Verdict counts
    verdict_result = await db.execute(text("""
        SELECT verdict, COUNT(*) as count
        FROM correlation_results
        GROUP BY verdict
    """))
    verdict_counts = {r["verdict"]: r["count"] for r in verdict_result.mappings().all()}

    # Recent alerts
    recent_result = await db.execute(text("""
        SELECT id, source, alert_type, severity, status, created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 10
    """))
    recent_alerts = [dict(r) for r in recent_result.mappings().all()]

    # Review queue size
    review_result = await db.execute(text("""
        SELECT COUNT(*) as count
        FROM alerts a
        JOIN correlation_results c ON c.alert_id = a.id
        WHERE c.verdict = 'uncertain' OR a.severity IN ('high', 'critical')
    """))
    review_count = review_result.scalar()

    return {
        "severity_counts": severity_counts,
        "verdict_counts": verdict_counts,
        "recent_alerts": recent_alerts,
        "review_queue_size": review_count,
        "total_alerts": sum(severity_counts.values()),
        "total_incidents": len(recent_alerts),
    }
