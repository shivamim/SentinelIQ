"""LangGraph state schema — SentinelIQ IncidentState."""
from typing import TypedDict, Literal, Optional, List, Dict, Any


class IncidentState(TypedDict):
    raw_alert: dict
    asset_context: dict
    similar_incidents: List[dict]
    relevant_cves: List[dict]
    mitre_techniques: List[dict]
    neo4j_paths: List[dict]           # Correlation paths from Neo4j
    reasoning: str
    verdict: Optional[Literal["known_pattern", "novel", "uncertain"]]
    confidence: float
    grounding_passed: bool
    retry_count: int
    severity: Optional[Literal["low", "medium", "high", "critical"]]
    escalate: bool
    report: str
    _cited_incident_ids: List[str]
    _cited_cve_ids: List[str]
    _cited_technique_ids: List[str]
