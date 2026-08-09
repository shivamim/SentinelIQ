"""LangGraph builder — 11 nodes with conditional edges, Redis checkpointer."""
from typing import Any, Dict, Literal
from langgraph.graph import StateGraph, END
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph.state import IncidentState
from app.graph.nodes import (
    parse_alert_node,
    asset_context_node,
    structured_history_node,
    vector_retrieval_node,
    mitre_mapping_node,
    correlation_reasoner_node,
    grounding_verifier_node,
    severity_classifier_node,
    human_escalation_node,
    report_generator_node,
    audit_logger_node,
)
from app.services.redis_checkpointer import get_checkpointer


def build_graph(db: AsyncSession):
    """Build and compile the LangGraph with all 11 nodes and conditional edges.

    Uses Redis/Upstash checkpointer for state persistence across restarts.
    """
    builder = StateGraph(IncidentState)

    # Add all nodes
    builder.add_node("parse_alert_node", parse_alert_node)
    builder.add_node("asset_context_node", lambda s: asset_context_node(s, db))
    builder.add_node("structured_history_node", lambda s: structured_history_node(s, db))
    builder.add_node("vector_retrieval_node", lambda s: vector_retrieval_node(s, db))
    builder.add_node("mitre_mapping_node", lambda s: mitre_mapping_node(s, db))
    builder.add_node("correlation_reasoner_node", correlation_reasoner_node)
    builder.add_node("grounding_verifier_node", grounding_verifier_node)
    builder.add_node("severity_classifier_node", severity_classifier_node)
    builder.add_node("human_escalation_node", human_escalation_node)
    builder.add_node("report_generator_node", report_generator_node)
    builder.add_node("audit_logger_node", lambda s: audit_logger_node(s, db))

    # Linear edges 1->2->3->4->5->6->7
    builder.set_entry_point("parse_alert_node")
    builder.add_edge("parse_alert_node", "asset_context_node")
    builder.add_edge("asset_context_node", "structured_history_node")
    builder.add_edge("structured_history_node", "vector_retrieval_node")
    builder.add_edge("vector_retrieval_node", "mitre_mapping_node")
    builder.add_edge("mitre_mapping_node", "correlation_reasoner_node")
    builder.add_edge("correlation_reasoner_node", "grounding_verifier_node")

    # Conditional loop 7->4 (not grounded, retry_count < 2) or 7->8 (grounded or retries exhausted)
    def grounding_router(state: IncidentState) -> Literal["vector_retrieval_node", "severity_classifier_node"]:
        if not state.get("grounding_passed", False) and state.get("retry_count", 0) < 2:
            return "vector_retrieval_node"
        return "severity_classifier_node"

    builder.add_conditional_edges(
        "grounding_verifier_node",
        grounding_router,
        {
            "vector_retrieval_node": "vector_retrieval_node",
            "severity_classifier_node": "severity_classifier_node",
        },
    )

    # Conditional branch 8->9 (escalate) or 8->10 (no escalate)
    def escalation_router(state: IncidentState) -> Literal["human_escalation_node", "report_generator_node"]:
        if state.get("escalate", False):
            return "human_escalation_node"
        return "report_generator_node"

    builder.add_conditional_edges(
        "severity_classifier_node",
        escalation_router,
        {
            "human_escalation_node": "human_escalation_node",
            "report_generator_node": "report_generator_node",
        },
    )

    # 9->10 after analyst action
    builder.add_edge("human_escalation_node", "report_generator_node")

    # 10->11
    builder.add_edge("report_generator_node", "audit_logger_node")

    # 11->END
    builder.add_edge("audit_logger_node", END)

    # Redis-backed checkpointer for production persistence
    checkpointer = get_checkpointer()
    return builder.compile(checkpointer=checkpointer)
