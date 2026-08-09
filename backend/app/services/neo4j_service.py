"""Neo4j knowledge graph service with real Cypher queries for asset/alert correlation."""
from typing import List, Dict, Any, Optional
from app.config import get_settings

settings = get_settings()


class Neo4jService:
    """Async Neo4j driver wrapper for SentinelIQ knowledge graph.

    The graph stores:
    - Asset nodes: (a:Asset {id, hostname, ip, criticality})
    - Alert nodes: (a:Alert {id, alert_type, severity})
    - Incident nodes: (i:Incident {id, title, severity})
    - Technique nodes: (t:Technique {id, name})

    Relationships:
    - (Alert)-[:TARGETS]->(Asset)
    - (Alert)-[:CORRELATES_TO]->(Incident)
    - (Alert)-[:USES_TECHNIQUE]->(Technique)
    - (Asset)-[:CONNECTED_TO]->(Asset)  — network adjacency
    """

    def __init__(self):
        self._driver = None

    def _get_driver(self):
        if self._driver is not None:
            return self._driver
        if not settings.NEO4J_URI or not settings.NEO4J_PASSWORD:
            raise RuntimeError(
                "NEO4J_URI and NEO4J_PASSWORD are required for the knowledge graph. "
                "Set these environment variables to enable Neo4j features."
            )
        from neo4j import AsyncGraphDatabase
        self._driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
        return self._driver

    async def close(self):
        if self._driver:
            await self._driver.close()
            self._driver = None

    async def _run(self, query: str, params: dict = None) -> List[dict]:
        driver = self._get_driver()
        async with driver.session() as session:
            result = await session.run(query, params or {})
            records = await result.data()
            return records

    # ---------- Node creation ----------

    async def create_asset_node(
        self, asset_id: str, hostname: str, ip: str, criticality: str
    ):
        """Create or update an Asset node in the knowledge graph."""
        await self._run("""
            MERGE (a:Asset {id: $asset_id})
            SET a.hostname = $hostname,
                a.ip = $ip,
                a.criticality = $criticality
        """, {"asset_id": asset_id, "hostname": hostname, "ip": ip, "criticality": criticality})

    async def create_alert_node(
        self, alert_id: str, alert_type: str, severity: str
    ):
        """Create an Alert node in the knowledge graph."""
        await self._run("""
            MERGE (a:Alert {id: $alert_id})
            SET a.alert_type = $alert_type,
                a.severity = $severity
        """, {"alert_id": alert_id, "alert_type": alert_type, "severity": severity})

    async def create_incident_node(
        self, incident_id: str, title: str, severity: str
    ):
        """Create an Incident node in the knowledge graph."""
        await self._run("""
            MERGE (i:Incident {id: $incident_id})
            SET i.title = $title,
                i.severity = $severity
        """, {"incident_id": incident_id, "title": title, "severity": severity})

    async def create_technique_node(
        self, technique_id: str, name: str
    ):
        """Create a MITRE ATT&CK Technique node."""
        await self._run("""
            MERGE (t:Technique {id: $technique_id})
            SET t.name = $name
        """, {"technique_id": technique_id, "name": name})

    # ---------- Relationship creation ----------

    async def link_alert_to_asset(self, alert_id: str, asset_id: str):
        """(Alert)-[:TARGETS]->(Asset)"""
        await self._run("""
            MATCH (a:Alert {id: $alert_id}), (b:Asset {id: $asset_id})
            MERGE (a)-[:TARGETS]->(b)
        """, {"alert_id": alert_id, "asset_id": asset_id})

    async def link_alert_to_incident(self, alert_id: str, incident_id: str):
        """(Alert)-[:CORRELATES_TO]->(Incident)"""
        await self._run("""
            MATCH (a:Alert {id: $alert_id}), (i:Incident {id: $incident_id})
            MERGE (a)-[:CORRELATES_TO]->(i)
        """, {"alert_id": alert_id, "incident_id": incident_id})

    async def link_alert_to_technique(self, alert_id: str, technique_id: str):
        """(Alert)-[:USES_TECHNIQUE]->(Technique)"""
        await self._run("""
            MATCH (a:Alert {id: $alert_id}), (t:Technique {id: $technique_id})
            MERGE (a)-[:USES_TECHNIQUE]->(t)
        """, {"alert_id": alert_id, "technique_id": technique_id})

    async def link_assets_connected(self, asset_a_id: str, asset_b_id: str, protocol: str = "unknown"):
        """(Asset)-[:CONNECTED_TO {protocol}]->(Asset) — network adjacency"""
        await self._run("""
            MATCH (a:Asset {id: $a_id}), (b:Asset {id: $b_id})
            MERGE (a)-[:CONNECTED_TO {protocol: $protocol}]->(b)
        """, {"a_id": asset_a_id, "b_id": asset_b_id, "protocol": protocol})

    # ---------- Graph queries ----------

    async def find_correlation_paths(self, alert_id: str, max_depth: int = 3) -> List[dict]:
        """Find all correlation paths from an alert up to max_depth hops.

        Cypher:
            MATCH path = (a:Alert {id: $alert_id})-[*1..3]-(related)
            RETURN path
        """
        results = await self._run(f"""
            MATCH path = (a:Alert {{id: $alert_id}})-[*1..{max_depth}]-(related)
            RETURN path
        """, {"alert_id": alert_id})
        return results

    async def find_attack_chains(self, asset_id: str) -> List[dict]:
        """Find multi-hop attack patterns originating from an asset.

        Finds: Asset <- TARGETS <- Alert -[:USES_TECHNIQUE]-> Technique
              and  Alert -[:CORRELATES_TO]-> Incident
        """
        results = await self._run("""
            MATCH (asset:Asset {id: $asset_id})<-[:TARGETS]-(alert:Alert)
            OPTIONAL MATCH (alert)-[:USES_TECHNIQUE]->(tech:Technique)
            OPTIONAL MATCH (alert)-[:CORRELATES_TO]->(inc:Incident)
            RETURN alert.id as alert_id, alert.alert_type as alert_type,
                   alert.severity as severity,
                   collect(DISTINCT tech.id) as techniques,
                   collect(DISTINCT inc.id) as incidents
            ORDER BY alert.severity DESC
        """, {"asset_id": asset_id})
        return results

    async def get_asset_blast_radius(self, asset_id: str) -> Dict[str, Any]:
        """Find all assets reachable from this asset within 2 hops.

        This answers: "If this asset is compromised, what else is at risk?"
        """
        results = await self._run("""
            MATCH (source:Asset {id: $asset_id})-[:CONNECTED_TO*1..2]-(reachable:Asset)
            RETURN reachable.id as asset_id, reachable.hostname as hostname,
                   reachable.ip as ip, reachable.criticality as criticality
        """, {"asset_id": asset_id})
        return {"source_asset": asset_id, "blast_radius": [dict(r) for r in results]}

    async def get_alert_timeline(self, asset_id: str, limit: int = 50) -> List[dict]:
        """Get chronological alert history for an asset from the graph."""
        results = await self._run("""
            MATCH (asset:Asset {id: $asset_id})<-[:TARGETS]-(alert:Alert)
            RETURN alert.id as alert_id, alert.alert_type as alert_type,
                   alert.severity as severity
            ORDER BY alert.id DESC
            LIMIT $limit
        """, {"asset_id": asset_id, "limit": limit})
        return [dict(r) for r in results]


# Singleton
neo4j_service = Neo4jService()
