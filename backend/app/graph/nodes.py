"""LangGraph nodes for SentinelIQ incident correlation pipeline — Groq LLM."""
import json
import uuid
from typing import Any, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.types import interrupt, Command

from app.graph.state import IncidentState
from app.graph.retrieval import StructuredRetrieval, HybridRetrieval
from app.services.embeddings import embedding_service
from app.services.neo4j_service import neo4j_service
from app.services.langfuse_trace import tracer
from app.config import get_settings

settings = get_settings()

# Lazy-init LLM
_llm = None

def get_llm():
    global _llm
    if _llm is None:
        if not settings.GROQ_API_KEY:
            raise RuntimeError(
                "GROQ_API_KEY is required — no fallback LLM provider. "
                "Set the GROQ_API_KEY environment variable."
            )
        _llm = ChatGroq(
            model=settings.GROQ_MODEL,
            groq_api_key=settings.GROQ_API_KEY,
            temperature=0.1,
            max_tokens=4096,
        )
    return _llm


# ---------- Node 1: parse_alert_node ----------
def parse_alert_node(state: IncidentState) -> Dict[str, Any]:
    """Normalize raw SIEM JSON into structured IOC fields."""
    raw = state["raw_alert"]
    # Handle both ECS-style and Wazuh-style schemas
    alert_type = raw.get("alert_type") or raw.get("rule", {}).get("description", "unknown")
    ioc_ip = raw.get("ioc_ip") or raw.get("source", {}).get("ip") or raw.get("src_ip")
    ioc_domain = raw.get("ioc_domain") or raw.get("dns", {}).get("question", {}).get("name")
    ioc_hash = raw.get("ioc_hash") or raw.get("file", {}).get("hash", {}).get("sha256")
    asset_id = raw.get("asset_id")
    severity = raw.get("severity") or raw.get("rule", {}).get("level")

    parsed = {
        "alert_type": alert_type,
        "ioc_ip": ioc_ip,
        "ioc_domain": ioc_domain,
        "ioc_hash": ioc_hash,
        "asset_id": asset_id,
        "severity_hint": severity,
    }
    return {"raw_alert": {**raw, "_parsed": parsed}}


# ---------- Node 2: asset_context_node ----------
async def asset_context_node(state: IncidentState, db: AsyncSession) -> Dict[str, Any]:
    """SQL lookup: asset criticality, owner team, environment.
    Also query Neo4j for correlation paths if available."""
    parsed = state["raw_alert"].get("_parsed", {})
    asset_id = parsed.get("asset_id")
    ctx = {}
    neo4j_paths = []

    if asset_id:
        ctx = await StructuredRetrieval.asset_context(db, asset_id) or {}

        # Query Neo4j for correlation paths
        try:
            paths = await neo4j_service.find_correlation_paths(asset_id, max_depth=2)
            neo4j_paths = paths
        except Exception:
            # Neo4j is optional — don't fail the pipeline if it's unavailable
            pass

    return {"asset_context": ctx, "neo4j_paths": neo4j_paths}


# ---------- Node 3: structured_history_node ----------
async def structured_history_node(state: IncidentState, db: AsyncSession) -> Dict[str, Any]:
    """Text-to-SQL agent: have we seen this IOC / asset / alert_type combo before?"""
    parsed = state["raw_alert"].get("_parsed", {})
    incidents = await StructuredRetrieval.history_by_ioc(
        db,
        ioc_ip=parsed.get("ioc_ip"),
        ioc_domain=parsed.get("ioc_domain"),
        ioc_hash=parsed.get("ioc_hash"),
        asset_id=parsed.get("asset_id"),
        alert_type=parsed.get("alert_type"),
    )
    return {"similar_incidents": incidents}


# ---------- Node 4: vector_retrieval_node ----------
async def vector_retrieval_node(state: IncidentState, db: AsyncSession) -> Dict[str, Any]:
    """Hybrid BM25 + vector search with RRF across postmortem + CVE embeddings."""
    parsed = state["raw_alert"].get("_parsed", {})
    alert_type = parsed.get("alert_type", "")
    ioc_ip = parsed.get("ioc_ip", "")
    ioc_domain = parsed.get("ioc_domain", "")
    query_text = f"{alert_type} {ioc_ip} {ioc_domain} intrusion alert".strip()

    embedding = embedding_service.embed([query_text])[0]

    cves = await HybridRetrieval.search_cves(db, query_text, embedding, top_k=20)
    postmortems = await HybridRetrieval.search_postmortems(db, query_text, embedding, top_k=20)

    return {
        "relevant_cves": cves,
        "similar_incidents": state.get("similar_incidents", []) + postmortems,
    }


# ---------- Node 5: mitre_mapping_node ----------
async def mitre_mapping_node(state: IncidentState, db: AsyncSession) -> Dict[str, Any]:
    """Retrieve likely ATT&CK technique(s) for this alert."""
    parsed = state["raw_alert"].get("_parsed", {})
    alert_type = parsed.get("alert_type", "")
    query_text = f"MITRE ATT&CK technique for {alert_type}"
    embedding = embedding_service.embed([query_text])[0]
    techniques = await HybridRetrieval.search_mitre(db, embedding, top_k=5)
    return {"mitre_techniques": techniques}


# ---------- Node 6: correlation_reasoner_node ----------
def correlation_reasoner_node(state: IncidentState) -> Dict[str, Any]:
    """LLM reasons over all context, drafts verdict + cited reasoning trace."""
    llm = get_llm()
    asset = state.get("asset_context", {})
    incidents = state.get("similar_incidents", [])
    cves = state.get("relevant_cves", [])
    techniques = state.get("mitre_techniques", [])
    neo4j_paths = state.get("neo4j_paths", [])

    incidents_text = json.dumps(incidents[:5], indent=2, default=str)
    cves_text = json.dumps(cves[:5], indent=2, default=str)
    techniques_text = json.dumps(techniques[:5], indent=2, default=str)
    raw_alert = json.dumps(state["raw_alert"], indent=2, default=str)

    system_prompt = """You are a senior SOC analyst. Your job is to classify an incoming SIEM alert as one of:
- known_pattern: matches a past incident or CVE pattern we have seen before
- novel: does not match any past pattern; potentially new threat
- uncertain: not enough context to decide

Rules:
1. Every claim MUST cite a specific incident_id, cve_id, or technique_id from the retrieved context.
2. If citing an incident, reference its id explicitly.
3. If citing a CVE, reference its cve_id explicitly.
4. If citing MITRE, reference technique_id explicitly.
5. Be concise but thorough.

Output JSON only:
{
  "verdict": "known_pattern|novel|uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "...",
  "cited_incident_ids": ["..."],
  "cited_cve_ids": ["..."],
  "cited_technique_ids": ["..."]
}
"""

    human_prompt = f"""Alert:
{raw_alert}

Asset Context:
{json.dumps(asset, indent=2)}

Similar Incidents / Postmortems:
{incidents_text}

Relevant CVEs:
{cves_text}

MITRE Techniques:
{techniques_text}

Neo4j Correlation Paths:
{json.dumps(neo4j_paths[:3], indent=2, default=str)}
"""

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt),
    ]
    response = llm.invoke(messages)
    content = response.content

    # Extract JSON
    try:
        # Handle markdown code blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        parsed_response = json.loads(content)
    except Exception:
        parsed_response = {
            "verdict": "uncertain",
            "confidence": 0.0,
            "reasoning": content,
            "cited_incident_ids": [],
            "cited_cve_ids": [],
            "cited_technique_ids": [],
        }

    return {
        "verdict": parsed_response.get("verdict", "uncertain"),
        "confidence": parsed_response.get("confidence", 0.0),
        "reasoning": parsed_response.get("reasoning", ""),
        "_cited_incident_ids": parsed_response.get("cited_incident_ids", []),
        "_cited_cve_ids": parsed_response.get("cited_cve_ids", []),
        "_cited_technique_ids": parsed_response.get("cited_technique_ids", []),
    }


# ---------- Node 7: grounding_verifier_node ----------
def grounding_verifier_node(state: IncidentState) -> Dict[str, Any]:
    """Check every claim cites a real ID returned by retrieval. If not, loop back."""
    incidents = state.get("similar_incidents", [])
    cves = state.get("relevant_cves", [])
    techniques = state.get("mitre_techniques", [])

    valid_incident_ids = {str(i.get("id", i.get("postmortem_id", ""))) for i in incidents}
    valid_cve_ids = {c.get("cve_id", "") for c in cves}
    valid_technique_ids = {t.get("technique_id", "") for t in techniques}

    cited_incidents = set(state.get("_cited_incident_ids", []))
    cited_cves = set(state.get("_cited_cve_ids", []))
    cited_techniques = set(state.get("_cited_technique_ids", []))

    bad_incidents = cited_incidents - valid_incident_ids
    bad_cves = cited_cves - valid_cve_ids
    bad_techniques = cited_techniques - valid_technique_ids

    grounded = not (bad_incidents or bad_cves or bad_techniques)
    retry = state.get("retry_count", 0)

    if not grounded and retry < 2:
        return {
            "grounding_passed": False,
            "retry_count": retry + 1,
            "reasoning": state.get("reasoning", "") + f"\n[GROUNDING FAIL: retry {retry + 1}]",
        }
    elif not grounded and retry >= 2:
        return {
            "grounding_passed": False,
            "retry_count": retry,
            "verdict": "uncertain",
            "reasoning": state.get("reasoning", "") + "\n[GROUNDING FAIL: retries exhausted; verdict forced to uncertain]",
        }
    else:
        return {"grounding_passed": True, "retry_count": retry}


# ---------- Node 8: severity_classifier_node ----------
def severity_classifier_node(state: IncidentState) -> Dict[str, Any]:
    """Combine asset criticality + CVE CVSS + historical severity -> final severity."""
    asset = state.get("asset_context", {})
    cves = state.get("relevant_cves", [])
    verdict = state.get("verdict", "uncertain")
    confidence = state.get("confidence", 0.0)

    asset_crit = asset.get("criticality", "low")
    max_cvss = max([c.get("cvss_score", 0) or 0 for c in cves], default=0)

    # Simple scoring matrix
    severity_score = 0
    if asset_crit == "critical":
        severity_score += 3
    elif asset_crit == "high":
        severity_score += 2
    elif asset_crit == "medium":
        severity_score += 1

    if max_cvss >= 9.0:
        severity_score += 3
    elif max_cvss >= 7.0:
        severity_score += 2
    elif max_cvss >= 4.0:
        severity_score += 1

    if verdict == "novel" and confidence > 0.7:
        severity_score += 1

    if severity_score >= 5:
        severity = "critical"
    elif severity_score >= 3:
        severity = "high"
    elif severity_score >= 1:
        severity = "medium"
    else:
        severity = "low"

    escalate = severity in ("high", "critical") or verdict == "uncertain"

    return {"severity": severity, "escalate": escalate}


# ---------- Node 9: human_escalation_node ----------
def human_escalation_node(state: IncidentState) -> Dict[str, Any]:
    """interrupt() if severity is high/critical OR verdict is uncertain."""
    # This node only runs when escalate=True
    decision = interrupt({
        "message": "Alert requires human review",
        "alert_summary": state["raw_alert"],
        "reasoning": state.get("reasoning", ""),
        "verdict": state.get("verdict"),
        "severity": state.get("severity"),
        "confidence": state.get("confidence"),
    })
    # decision comes back from Command(resume=...)
    return {
        "verdict": decision.get("verdict", state.get("verdict")),
        "reasoning": decision.get("reasoning", state.get("reasoning", "")),
        "severity": decision.get("severity", state.get("severity")),
    }


# ---------- Node 10: report_generator_node ----------
def report_generator_node(state: IncidentState) -> Dict[str, Any]:
    """Draft incident summary with inline citations."""
    incidents = state.get("similar_incidents", [])
    cves = state.get("relevant_cves", [])
    techniques = state.get("mitre_techniques", [])

    citations = []
    for i in incidents[:3]:
        cid = i.get("id") or i.get("postmortem_id")
        if cid:
            citations.append(f"[Incident: {cid}]")
    for c in cves[:3]:
        if c.get("cve_id"):
            citations.append(f"[CVE: {c['cve_id']}]")
    for t in techniques[:3]:
        if t.get("technique_id"):
            citations.append(f"[MITRE: {t['technique_id']}]")

    report = f"""## Incident Correlation Report

**Verdict:** {state.get("verdict", "unknown")}
**Severity:** {state.get("severity", "unknown")}
**Confidence:** {state.get("confidence", 0.0):.2f}
**Grounding Passed:** {state.get("grounding_passed", False)}

### Reasoning
{state.get("reasoning", "No reasoning provided.")}

### Citations
{chr(10).join(citations) if citations else "None"}
"""
    return {"report": report}


# ---------- Node 11: audit_logger_node ----------
async def audit_logger_node(state: IncidentState, db: AsyncSession) -> Dict[str, Any]:
    """Write correlation_results row + audit_log entry."""
    from sqlalchemy import text
    from app.models import CorrelationResult, AuditLog

    alert_id = state["raw_alert"].get("id")
    if not alert_id:
        return {}

    # Build matched lists from state
    incident_ids = []
    for i in state.get("similar_incidents", []):
        iid = i.get("id") or i.get("postmortem_id")
        if iid:
            incident_ids.append(iid)

    cve_ids = [c.get("cve_id") for c in state.get("relevant_cves", []) if c.get("cve_id")]
    tech_ids = [t.get("technique_id") for t in state.get("mitre_techniques", []) if t.get("technique_id")]

    # Insert correlation result
    corr_sql = text("""
        INSERT INTO correlation_results
        (alert_id, matched_incident_ids, matched_cve_ids, matched_mitre_techniques,
         reasoning_text, confidence_score, verdict, grounding_passed, retry_count)
        VALUES (:alert_id, :incident_ids, :cve_ids, :tech_ids,
                :reasoning, :confidence, :verdict, :grounding, :retries)
    """)
    await db.execute(corr_sql, {
        "alert_id": alert_id,
        "incident_ids": incident_ids,
        "cve_ids": cve_ids,
        "tech_ids": tech_ids,
        "reasoning": state.get("reasoning", ""),
        "confidence": state.get("confidence", 0.0),
        "verdict": state.get("verdict"),
        "grounding": state.get("grounding_passed", False),
        "retries": state.get("retry_count", 0),
    })

    # Insert audit log
    audit_sql = text("""
        INSERT INTO audit_log (actor, action, entity_type, entity_id, metadata)
        VALUES (:actor, :action, :entity_type, :entity_id, :metadata)
    """)
    await db.execute(audit_sql, {
        "actor": "sentineliq_agent",
        "action": "correlation_completed",
        "entity_type": "alert",
        "entity_id": alert_id,
        "metadata": {
            "verdict": state.get("verdict"),
            "severity": state.get("severity"),
            "escalated": state.get("escalate", False),
        },
    })
    await db.commit()
    return {}
