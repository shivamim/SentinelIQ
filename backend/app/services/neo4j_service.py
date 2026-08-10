"""Neo4j knowledge graph service for SentinelIQ."""

from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import get_settings
from app.models import Alert, Asset, Incident, CorrelationResult


settings = get_settings()


class Neo4jService:
    """
    Async Neo4j driver wrapper for SentinelIQ.

    Graph structure:

        Alert
          ├── TARGETS ────────> Asset
          ├── CORRELATES_TO ──> Incident
          └── USES_TECHNIQUE ─> Technique

        Asset
          └── CONNECTED_TO ───> Asset
    """

    def __init__(self):
        self._driver = None

    # ==========================================================
    # DRIVER
    # ==========================================================

    def _get_driver(self):
        if self._driver is not None:
            return self._driver

        if (
            not settings.NEO4J_URI
            or not settings.NEO4J_PASSWORD
        ):
            raise RuntimeError(
                "NEO4J_URI and NEO4J_PASSWORD are required "
                "for the knowledge graph."
            )

        from neo4j import AsyncGraphDatabase

        self._driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(
                settings.NEO4J_USER,
                settings.NEO4J_PASSWORD,
            ),
        )

        return self._driver

    async def close(self):
        if self._driver:
            await self._driver.close()
            self._driver = None

    async def _run(
        self,
        query: str,
        params: Optional[dict] = None,
    ) -> List[dict]:

        driver = self._get_driver()

        async with driver.session() as session:
            result = await session.run(
                query,
                params or {},
            )

            return await result.data()

    # ==========================================================
    # HEALTH / DEBUG
    # ==========================================================

    async def health_check(self) -> Dict[str, Any]:
        """
        Return Neo4j connection status and node counts.
        
        Returns:
            {
                "connected": bool,
                "database": str,
                "alert_count": int,
                "asset_count": int,
                "incident_count": int,
                "technique_count": int
            }
        """
        try:
            driver = self._get_driver()
            
            # Test connection and get database info
            async with driver.session() as session:
                result = await session.run("CALL dbms.components() YIELD name, versions RETURN name, versions[0] AS version")
                record = await result.single()
                
                if not record:
                    return {
                        "connected": False,
                        "error": "No response from Neo4j"
                    }
                
                database_info = {
                    "connected": True,
                    "database": record.get("name", "unknown"),
                    "version": record.get("version", "unknown")
                }
            
            # Get node counts
            alert_result = await self._run("MATCH (a:Alert) RETURN count(a) AS count")
            asset_result = await self._run("MATCH (a:Asset) RETURN count(a) AS count")
            incident_result = await self._run("MATCH (i:Incident) RETURN count(i) AS count")
            technique_result = await self._run("MATCH (t:Technique) RETURN count(t) AS count")
            
            database_info["alert_count"] = alert_result[0]["count"] if alert_result else 0
            database_info["asset_count"] = asset_result[0]["count"] if asset_result else 0
            database_info["incident_count"] = incident_result[0]["count"] if incident_result else 0
            database_info["technique_count"] = technique_result[0]["count"] if technique_result else 0
            
            return database_info
            
        except Exception as e:
            return {
                "connected": False,
                "error": str(e)
            }

    # ==========================================================
    # SYNCHRONIZATION FROM POSTGRESQL
    # ==========================================================

    async def sync_alert_from_postgres(
        self,
        db: AsyncSession,
        alert_id: str,
    ) -> Dict[str, Any]:
        """
        Synchronize an alert from PostgreSQL to Neo4j along with
        all related entities (Asset, Incident, Technique).
        
        This ensures the graph is populated on-demand when querying
        for attack replay.
        
        Args:
            db: PostgreSQL async session
            alert_id: Full UUID string of the alert
            
        Returns:
            Dict with sync status and counts
        """
        from uuid import UUID
        
        # Validate UUID format
        try:
            uuid_obj = UUID(alert_id)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid alert ID format: {alert_id}"
            }
        
        # Load alert from PostgreSQL
        result = await db.execute(
            select(Alert).where(Alert.id == uuid_obj)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            return {
                "success": False,
                "error": f"Alert not found in PostgreSQL: {alert_id}"
            }
        
        # Create/update Alert node in Neo4j
        await self.create_alert_node(
            alert_id=str(alert.id),
            alert_type=alert.alert_type or "unknown",
            severity=alert.severity or "unknown"
        )
        
        synced = {
            "alert_created": True,
            "asset_linked": False,
            "incidents_linked": 0,
            "techniques_linked": 0
        }
        
        # Link to Asset if present
        if alert.asset_id:
            asset_result = await db.execute(
                select(Asset).where(Asset.id == alert.asset_id)
            )
            asset = asset_result.scalar_one_or_none()
            
            if asset:
                await self.create_asset_node(
                    asset_id=str(asset.id),
                    hostname=asset.hostname or "unknown",
                    ip=asset.ip_address or "unknown",
                    criticality=asset.criticality or "unknown"
                )
                
                await self.link_alert_to_asset(
                    alert_id=str(alert.id),
                    asset_id=str(asset.id)
                )
                
                synced["asset_linked"] = True
        
        # Load correlation result to get incidents and techniques
        corr_result = await db.execute(
            select(CorrelationResult).where(
                CorrelationResult.alert_id == uuid_obj
            )
        )
        correlation = corr_result.scalar_one_or_none()
        
        if correlation:
            # Link to Incidents
            matched_incidents = correlation.matched_incident_ids or []
            
            for incident_uuid in matched_incidents:
                incident_result = await db.execute(
                    select(Incident).where(Incident.id == incident_uuid)
                )
                incident = incident_result.scalar_one_or_none()
                
                if incident:
                    await self.create_incident_node(
                        incident_id=str(incident.id),
                        title=incident.title or "unknown",
                        severity=incident.severity or "unknown"
                    )
                    
                    await self.link_alert_to_incident(
                        alert_id=str(alert.id),
                        incident_id=str(incident.id)
                    )
                    
                    synced["incidents_linked"] += 1
            
            # Link to MITRE Techniques
            matched_techniques = correlation.matched_mitre_techniques or []
            
            for technique_id in matched_techniques:
                # Extract technique name from ID if possible (e.g., T1110 -> Brute Force)
                technique_name = f"Technique {technique_id}"
                
                await self.create_technique_node(
                    technique_id=technique_id,
                    name=technique_name
                )
                
                await self.link_alert_to_technique(
                    alert_id=str(alert.id),
                    technique_id=technique_id
                )
                
                synced["techniques_linked"] += 1
        
        return {
            "success": True,
            "alert_id": str(alert.id),
            **synced
        }

    # ==========================================================
    # NODE CREATION
    # ==========================================================

    async def create_asset_node(
        self,
        asset_id: str,
        hostname: str,
        ip: str,
        criticality: str,
    ):
        """Create or update an Asset node."""

        await self._run(
            """
            MERGE (a:Asset {id: $asset_id})

            SET
                a.hostname = $hostname,
                a.ip = $ip,
                a.criticality = $criticality
            """,
            {
                "asset_id": asset_id,
                "hostname": hostname,
                "ip": ip,
                "criticality": criticality,
            },
        )

    async def create_alert_node(
        self,
        alert_id: str,
        alert_type: str,
        severity: str,
    ):
        """Create or update an Alert node."""

        await self._run(
            """
            MERGE (a:Alert {id: $alert_id})

            SET
                a.alert_type = $alert_type,
                a.severity = $severity
            """,
            {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "severity": severity,
            },
        )

    async def create_incident_node(
        self,
        incident_id: str,
        title: str,
        severity: str,
    ):
        """Create or update an Incident node."""

        await self._run(
            """
            MERGE (i:Incident {id: $incident_id})

            SET
                i.title = $title,
                i.severity = $severity
            """,
            {
                "incident_id": incident_id,
                "title": title,
                "severity": severity,
            },
        )

    async def create_technique_node(
        self,
        technique_id: str,
        name: str,
    ):
        """Create or update a MITRE ATT&CK Technique node."""

        await self._run(
            """
            MERGE (t:Technique {id: $technique_id})

            SET
                t.name = $name
            """,
            {
                "technique_id": technique_id,
                "name": name,
            },
        )

    # ==========================================================
    # RELATIONSHIPS
    # ==========================================================

    async def link_alert_to_asset(
        self,
        alert_id: str,
        asset_id: str,
    ):
        """Alert -> Asset."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (b:Asset {id: $asset_id})

            MERGE (a)-[:TARGETS]->(b)
            """,
            {
                "alert_id": alert_id,
                "asset_id": asset_id,
            },
        )

    async def link_alert_to_incident(
        self,
        alert_id: str,
        incident_id: str,
    ):
        """Alert -> Incident."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (i:Incident {id: $incident_id})

            MERGE (a)-[:CORRELATES_TO]->(i)
            """,
            {
                "alert_id": alert_id,
                "incident_id": incident_id,
            },
        )

    async def link_alert_to_technique(
        self,
        alert_id: str,
        technique_id: str,
    ):
        """Alert -> MITRE Technique."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (t:Technique {id: $technique_id})

            MERGE (a)-[:USES_TECHNIQUE]->(t)
            """,
            {
                "alert_id": alert_id,
                "technique_id": technique_id,
            },
        )

    async def link_assets_connected(
        self,
        asset_a_id: str,
        asset_b_id: str,
        protocol: str = "unknown",
    ):
        """Asset -> Asset network relationship."""

        await self._run(
            """
            MATCH
                (a:Asset {id: $a_id}),
                (b:Asset {id: $b_id})

            MERGE (
                a
            )-[:CONNECTED_TO {
                protocol: $protocol
            }]->(
                b
            )
            """,
            {
                "a_id": asset_a_id,
                "b_id": asset_b_id,
                "protocol": protocol,
            },
        )

    # ==========================================================
    # ATTACK REPLAY GRAPH
    # ==========================================================

    async def get_attack_replay_graph(
        self,
        alert_id: str,
        max_depth: int = 3,
    ) -> Dict[str, Any]:
        """
        Return a JSON-safe graph for Attack Replay.

        First checks if the Alert node exists in Neo4j.
        If not, returns an honest response indicating the graph
        needs to be populated.

        The response contains:

            {
                "alert_id": "...",
                "nodes": [...],
                "edges": [...],
                "message": "..." (optional)
            }

        This is intentionally converted here instead of returning
        raw Neo4j Path objects to FastAPI.
        """

        if max_depth < 1:
            max_depth = 1

        if max_depth > 5:
            max_depth = 5

        # ------------------------------------------------------
        # First, check if the Alert node exists
        # ------------------------------------------------------

        check_query = """
        MATCH (start:Alert {id: $alert_id})
        RETURN start
        """

        check_results = await self._run(
            check_query,
            {
                "alert_id": alert_id,
            },
        )

        if not check_results or not check_results[0].get("start"):
            # Alert node does not exist in Neo4j
            return {
                "alert_id": alert_id,
                "nodes": [],
                "edges": [],
                "message": (
                    "Alert node not found in Neo4j. "
                    "The graph may need to be synchronized from PostgreSQL."
                )
            }

        # ------------------------------------------------------
        # Find the alert and all connected graph entities.
        #
        # Direction is deliberately unrestricted so the replay
        # can show the complete local attack graph.
        # ------------------------------------------------------

        query = f"""
        MATCH (start:Alert {{id: $alert_id}})

        OPTIONAL MATCH path =
            (start)-[*1..{max_depth}]-(related)

        WITH
            start,
            collect(DISTINCT related) AS related_nodes

        RETURN
            start,
            related_nodes
        """

        results = await self._run(
            query,
            {
                "alert_id": alert_id,
            },
        )

        if not results:
            return {
                "alert_id": alert_id,
                "nodes": [],
                "edges": [],
                "message": "Alert exists but no related Neo4j relationships were found."
            }

        record = results[0]

        start_node = record.get("start")
        related_nodes = record.get(
            "related_nodes",
            [],
        )

        # ------------------------------------------------------
        # Node serialization
        # ------------------------------------------------------

        node_map: Dict[str, Dict[str, Any]] = {}

        def serialize_node(node):
            if node is None:
                return None

            properties = dict(
                node.items()
            )

            node_id = str(
                properties.get("id")
            )

            labels = list(
                node.labels
            )

            if not node_id:
                return None

            # Determine graph type
            if "Alert" in labels:
                node_type = "alert"

            elif "Asset" in labels:
                node_type = "asset"

            elif "Incident" in labels:
                node_type = "incident"

            elif "Technique" in labels:
                node_type = "technique"

            else:
                node_type = "unknown"

            return {
                "id": node_id,
                "type": node_type,
                "labels": labels,
                "properties": properties,
            }

        # Add starting alert
        serialized = serialize_node(
            start_node
        )

        if serialized:
            node_map[
                serialized["id"]
            ] = serialized

        # Add connected nodes
        for node in related_nodes:

            serialized = serialize_node(
                node
            )

            if serialized:
                node_map[
                    serialized["id"]
                ] = serialized

        # ------------------------------------------------------
        # Retrieve relationships separately.
        #
        # This is much easier to serialize than raw Path objects.
        # ------------------------------------------------------

        relationship_query = f"""
        MATCH
            (start:Alert {{id: $alert_id}})
            -[r*1..{max_depth}]-
            (related)

        UNWIND r AS relationship

        WITH DISTINCT
            startNode(relationship) AS source,
            relationship,
            endNode(relationship) AS target

        RETURN
            source,
            type(relationship) AS relationship_type,
            target
        """

        relationship_rows = await self._run(
            relationship_query,
            {
                "alert_id": alert_id,
            },
        )

        edges: List[Dict[str, Any]] = []

        edge_seen = set()

        for row in relationship_rows:

            source = row.get(
                "source"
            )

            target = row.get(
                "target"
            )

            relationship_type = row.get(
                "relationship_type"
            )

            source_data = serialize_node(
                source
            )

            target_data = serialize_node(
                target
            )

            if not source_data or not target_data:
                continue

            source_id = source_data["id"]
            target_id = target_data["id"]

            node_map[
                source_id
            ] = source_data

            node_map[
                target_id
            ] = target_data

            edge_key = (
                source_id,
                relationship_type,
                target_id,
            )

            if edge_key in edge_seen:
                continue

            edge_seen.add(
                edge_key
            )

            edges.append(
                {
                    "id": (
                        f"{source_id}-"
                        f"{relationship_type}-"
                        f"{target_id}"
                    ),
                    "source": source_id,
                    "target": target_id,
                    "type": "default",
                    "relationship": relationship_type,
                }
            )

        response = {
            "alert_id": alert_id,
            "nodes": list(
                node_map.values()
            ),
            "edges": edges,
        }

        # Add message if no relationships found
        if not edges:
            response["message"] = (
                "Alert exists but no related Neo4j relationships were found."
            )

        return response

    # ==========================================================
    # EXISTING GRAPH QUERIES
    # ==========================================================

    async def find_correlation_paths(
        self,
        alert_id: str,
        max_depth: int = 3,
    ) -> List[dict]:
        """Find correlation paths from an alert."""

        if max_depth < 1:
            max_depth = 1

        if max_depth > 5:
            max_depth = 5

        results = await self._run(
            f"""
            MATCH path =
                (a:Alert {{id: $alert_id}})
                -[*1..{max_depth}]-
                (related)

            RETURN path
            """,
            {
                "alert_id": alert_id,
            },
        )

        return results

    async def find_attack_chains(
        self,
        asset_id: str,
    ) -> List[dict]:
        """Find attack patterns originating from an asset."""

        results = await self._run(
            """
            MATCH
                (asset:Asset {id: $asset_id})
                <-[:TARGETS]-
                (alert:Alert)

            OPTIONAL MATCH
                (alert)-[:USES_TECHNIQUE]->(tech:Technique)

            OPTIONAL MATCH
                (alert)-[:CORRELATES_TO]->(inc:Incident)

            RETURN
                alert.id AS alert_id,
                alert.alert_type AS alert_type,
                alert.severity AS severity,
                collect(DISTINCT tech.id) AS techniques,
                collect(DISTINCT inc.id) AS incidents

            ORDER BY alert.severity DESC
            """,
            {
                "asset_id": asset_id,
            },
        )

        return results

    async def get_asset_blast_radius(
        self,
        asset_id: str,
    ) -> Dict[str, Any]:
        """Find assets reachable within two hops."""

        results = await self._run(
            """
            MATCH
                (source:Asset {id: $asset_id})
                -[:CONNECTED_TO*1..2]-
                (reachable:Asset)

            RETURN
                reachable.id AS asset_id,
                reachable.hostname AS hostname,
                reachable.ip AS ip,
                reachable.criticality AS criticality
            """,
            {
                "asset_id": asset_id,
            },
        )

        return {
            "source_asset": asset_id,
            "blast_radius": [
                dict(row)
                for row in results
            ],
        }

    async def get_alert_timeline(
        self,
        asset_id: str,
        limit: int = 50,
    ) -> List[dict]:
        """Get alert history for an asset."""

        results = await self._run(
            """
            MATCH
                (asset:Asset {id: $asset_id})
                <-[:TARGETS]-
                (alert:Alert)

            RETURN
                alert.id AS alert_id,
                alert.alert_type AS alert_type,
                alert.severity AS severity

            ORDER BY alert.id DESC

            LIMIT $limit
            """,
            {
                "asset_id": asset_id,
                "limit": limit,
            },
        )

        return [
            dict(row)
            for row in results
        ]


# ============================================================
# Singleton
# ============================================================

neo4j_service = Neo4jService()
