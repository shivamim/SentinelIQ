"""Neo4j knowledge graph service for SentinelIQ."""

from typing import List, Dict, Any, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import get_settings
from app.models import (
    Alert,
    Asset,
    Incident,
    CorrelationResult,
)


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
        """Create and cache the Neo4j async driver."""

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
        """Close the Neo4j driver."""

        if self._driver:
            await self._driver.close()
            self._driver = None

    async def _run(
        self,
        query: str,
        params: Optional[dict] = None,
    ) -> List[dict]:
        """
        Execute a Cypher query and return JSON-friendly records.

        Neo4j Record objects are converted to dictionaries.
        """

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
        Return Neo4j connection status and graph statistics.

        Example:

        {
            "connected": true,
            "database": "neo4j",
            "version": "5.x",
            "alert_count": 1,
            "asset_count": 1,
            "incident_count": 1,
            "technique_count": 2
        }
        """

        try:
            driver = self._get_driver()

            # --------------------------------------------------
            # Test connection
            # --------------------------------------------------

            async with driver.session() as session:
                result = await session.run(
                    """
                    RETURN
                        1 AS ok
                    """
                )

                record = await result.single()

                if not record:
                    return {
                        "connected": False,
                        "error": "Neo4j returned no response.",
                    }

            # --------------------------------------------------
            # Count nodes
            # --------------------------------------------------

            alert_result = await self._run(
                """
                MATCH (a:Alert)
                RETURN count(a) AS count
                """
            )

            asset_result = await self._run(
                """
                MATCH (a:Asset)
                RETURN count(a) AS count
                """
            )

            incident_result = await self._run(
                """
                MATCH (i:Incident)
                RETURN count(i) AS count
                """
            )

            technique_result = await self._run(
                """
                MATCH (t:Technique)
                RETURN count(t) AS count
                """
            )

            return {
                "connected": True,
                "database": "neo4j",
                "version": "5.x",
                "alert_count": (
                    alert_result[0]["count"]
                    if alert_result
                    else 0
                ),
                "asset_count": (
                    asset_result[0]["count"]
                    if asset_result
                    else 0
                ),
                "incident_count": (
                    incident_result[0]["count"]
                    if incident_result
                    else 0
                ),
                "technique_count": (
                    technique_result[0]["count"]
                    if technique_result
                    else 0
                ),
            }

        except Exception as exc:
            return {
                "connected": False,
                "error": str(exc),
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
        Synchronize one PostgreSQL alert and all of its
        related entities into Neo4j.

        PostgreSQL:
            Alert
              ├── Asset
              └── CorrelationResult
                    ├── Incident(s)
                    └── MITRE Technique(s)

        Neo4j:
            Alert
              ├── TARGETS -> Asset
              ├── CORRELATES_TO -> Incident
              └── USES_TECHNIQUE -> Technique
        """

        # ------------------------------------------------------
        # 1. Validate UUID
        # ------------------------------------------------------

        try:
            uuid_obj = UUID(str(alert_id))
        except (ValueError, TypeError, AttributeError):
            return {
                "success": False,
                "error": f"Invalid alert UUID: {alert_id}",
            }

        normalized_alert_id = str(uuid_obj)

        # ------------------------------------------------------
        # 2. Load Alert from PostgreSQL
        # ------------------------------------------------------

        result = await db.execute(
            select(Alert).where(
                Alert.id == uuid_obj
            )
        )

        alert = result.scalar_one_or_none()

        if not alert:
            return {
                "success": False,
                "error": (
                    "Alert not found in PostgreSQL: "
                    f"{normalized_alert_id}"
                ),
            }

        # ------------------------------------------------------
        # 3. Create / update Alert node
        # ------------------------------------------------------

        await self.create_alert_node(
            alert_id=normalized_alert_id,
            alert_type=str(
                alert.alert_type
                or "unknown"
            ),
            severity=str(
                alert.severity
                or "unknown"
            ),
        )

        synced = {
            "alert_created": True,
            "asset_linked": False,
            "incidents_linked": 0,
            "techniques_linked": 0,
        }

        # ------------------------------------------------------
        # 4. Synchronize Asset
        # ------------------------------------------------------

        if alert.asset_id:

            asset_result = await db.execute(
                select(Asset).where(
                    Asset.id == alert.asset_id
                )
            )

            asset = asset_result.scalar_one_or_none()

            if asset:

                # IMPORTANT:
                # PostgreSQL INET becomes IPv4Address / IPv6Address.
                # Neo4j should receive a string instead.
                ip_value = (
                    str(asset.ip_address)
                    if asset.ip_address is not None
                    else "unknown"
                )

                await self.create_asset_node(
                    asset_id=str(asset.id),
                    hostname=str(
                        asset.hostname
                        or "unknown"
                    ),
                    ip=ip_value,
                    criticality=str(
                        asset.criticality
                        or "unknown"
                    ),
                )

                await self.link_alert_to_asset(
                    alert_id=normalized_alert_id,
                    asset_id=str(asset.id),
                )

                synced["asset_linked"] = True

        # ------------------------------------------------------
        # 5. Load CorrelationResult
        # ------------------------------------------------------

        corr_result = await db.execute(
            select(CorrelationResult)
            .where(
                CorrelationResult.alert_id
                == uuid_obj
            )
            .order_by(
                CorrelationResult.created_at.desc()
            )
        )

        # We only need the newest correlation result.
        correlation = (
            corr_result.scalars().first()
        )

        if correlation:

            # --------------------------------------------------
            # 6. Synchronize Incidents
            # --------------------------------------------------

            matched_incidents = (
                correlation.matched_incident_ids
                or []
            )

            for incident_uuid in matched_incidents:

                try:
                    incident_uuid_obj = UUID(
                        str(incident_uuid)
                    )
                except (
                    ValueError,
                    TypeError,
                    AttributeError,
                ):
                    continue

                incident_result = await db.execute(
                    select(Incident).where(
                        Incident.id
                        == incident_uuid_obj
                    )
                )

                incident = (
                    incident_result.scalar_one_or_none()
                )

                if not incident:
                    continue

                await self.create_incident_node(
                    incident_id=str(
                        incident.id
                    ),
                    title=str(
                        incident.title
                        or "unknown"
                    ),
                    severity=str(
                        incident.severity
                        or "unknown"
                    ),
                )

                await self.link_alert_to_incident(
                    alert_id=normalized_alert_id,
                    incident_id=str(
                        incident.id
                    ),
                )

                synced[
                    "incidents_linked"
                ] += 1

            # --------------------------------------------------
            # 7. Synchronize MITRE Techniques
            # --------------------------------------------------

            matched_techniques = (
                correlation.matched_mitre_techniques
                or []
            )

            for technique_id in matched_techniques:

                if technique_id is None:
                    continue

                technique_id = str(
                    technique_id
                ).strip()

                if not technique_id:
                    continue

                technique_name = (
                    f"Technique {technique_id}"
                )

                await self.create_technique_node(
                    technique_id=technique_id,
                    name=technique_name,
                )

                await self.link_alert_to_technique(
                    alert_id=normalized_alert_id,
                    technique_id=technique_id,
                )

                synced[
                    "techniques_linked"
                ] += 1

        return {
            "success": True,
            "alert_id": normalized_alert_id,
            **synced,
        }

    # ==========================================================
    # NODE CREATION
    # ==========================================================

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
                "alert_id": str(alert_id),
                "alert_type": str(
                    alert_type or "unknown"
                ),
                "severity": str(
                    severity or "unknown"
                ),
            },
        )

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
                "asset_id": str(asset_id),
                "hostname": str(
                    hostname or "unknown"
                ),
                "ip": str(
                    ip or "unknown"
                ),
                "criticality": str(
                    criticality or "unknown"
                ),
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
                "incident_id": str(
                    incident_id
                ),
                "title": str(
                    title or "unknown"
                ),
                "severity": str(
                    severity or "unknown"
                ),
            },
        )

    async def create_technique_node(
        self,
        technique_id: str,
        name: str,
    ):
        """Create or update a MITRE Technique node."""

        await self._run(
            """
            MERGE (t:Technique {id: $technique_id})

            SET
                t.name = $name
            """,
            {
                "technique_id": str(
                    technique_id
                ),
                "name": str(
                    name or technique_id
                ),
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
        """Create Alert -> Asset TARGETS relationship."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (b:Asset {id: $asset_id})

            MERGE (a)-[:TARGETS]->(b)
            """,
            {
                "alert_id": str(alert_id),
                "asset_id": str(asset_id),
            },
        )

    async def link_alert_to_incident(
        self,
        alert_id: str,
        incident_id: str,
    ):
        """Create Alert -> Incident relationship."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (i:Incident {id: $incident_id})

            MERGE (a)-[:CORRELATES_TO]->(i)
            """,
            {
                "alert_id": str(alert_id),
                "incident_id": str(incident_id),
            },
        )

    async def link_alert_to_technique(
        self,
        alert_id: str,
        technique_id: str,
    ):
        """Create Alert -> Technique relationship."""

        await self._run(
            """
            MATCH
                (a:Alert {id: $alert_id}),
                (t:Technique {id: $technique_id})

            MERGE (a)-[:USES_TECHNIQUE]->(t)
            """,
            {
                "alert_id": str(alert_id),
                "technique_id": str(
                    technique_id
                ),
            },
        )

    async def link_assets_connected(
        self,
        asset_a_id: str,
        asset_b_id: str,
        protocol: str = "unknown",
    ):
        """Create Asset -> Asset CONNECTED_TO relationship."""

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
                "a_id": str(asset_a_id),
                "b_id": str(asset_b_id),
                "protocol": str(
                    protocol or "unknown"
                ),
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

        Response:

        {
            "alert_id": "...",
            "nodes": [
                {
                    "id": "...",
                    "type": "alert",
                    "labels": ["Alert"],
                    "properties": {...}
                }
            ],
            "edges": [
                {
                    "id": "...",
                    "source": "...",
                    "target": "...",
                    "relationship": "TARGETS",
                    "type": "default"
                }
            ]
        }
        """

        # ------------------------------------------------------
        # Normalize UUID
        # ------------------------------------------------------

        try:
            alert_uuid = UUID(str(alert_id))
        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            return {
                "alert_id": str(alert_id),
                "nodes": [],
                "edges": [],
                "message": (
                    "Invalid alert UUID."
                ),
            }

        normalized_alert_id = str(
            alert_uuid
        )

        # ------------------------------------------------------
        # Limit traversal depth
        # ------------------------------------------------------

        try:
            max_depth = int(max_depth)
        except (
            ValueError,
            TypeError,
        ):
            max_depth = 3

        max_depth = max(
            1,
            min(max_depth, 5),
        )

        # ------------------------------------------------------
        # Check Alert node
        # ------------------------------------------------------

        check_query = """
        MATCH (start:Alert {id: $alert_id})
        RETURN start
        """

        check_results = await self._run(
            check_query,
            {
                "alert_id": normalized_alert_id,
            },
        )

        if (
            not check_results
            or not check_results[0].get("start")
        ):
            return {
                "alert_id": normalized_alert_id,
                "nodes": [],
                "edges": [],
                "message": (
                    "Alert node not found in Neo4j. "
                    "The graph has not been synchronized yet."
                ),
            }

        # ------------------------------------------------------
        # Find connected nodes
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
                "alert_id": normalized_alert_id,
            },
        )

        if not results:
            return {
                "alert_id": normalized_alert_id,
                "nodes": [],
                "edges": [],
                "message": (
                    "Alert exists but no related "
                    "Neo4j relationships were found."
                ),
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

        node_map: Dict[
            str,
            Dict[str, Any],
        ] = {}

        def serialize_node(node):
            """
            Convert a Neo4j Node into the frontend format.
            """

            if node is None:
                return None

            properties = dict(
                node.items()
            )

            # IMPORTANT:
            # Do not convert missing ID into "None".
            node_id = properties.get(
                "id"
            )

            if node_id is None:
                return None

            node_id = str(
                node_id
            )

            labels = [
                str(label)
                for label in node.labels
            ]

            # Determine frontend node type.
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

            # Make all property values JSON safe.
            safe_properties = {}

            for key, value in properties.items():

                if value is None:
                    safe_properties[
                        key
                    ] = None

                elif isinstance(
                    value,
                    (
                        str,
                        int,
                        float,
                        bool,
                    ),
                ):
                    safe_properties[
                        key
                    ] = value

                else:
                    safe_properties[
                        key
                    ] = str(value)

            return {
                "id": node_id,
                "type": node_type,
                "labels": labels,
                "properties": safe_properties,
            }

        # ------------------------------------------------------
        # Add starting Alert
        # ------------------------------------------------------

        serialized_start = (
            serialize_node(
                start_node
            )
        )

        if serialized_start:
            node_map[
                serialized_start["id"]
            ] = serialized_start

        # ------------------------------------------------------
        # Add connected nodes
        # ------------------------------------------------------

        for node in related_nodes:

            serialized = (
                serialize_node(node)
            )

            if serialized:
                node_map[
                    serialized["id"]
                ] = serialized

        # ------------------------------------------------------
        # Retrieve relationships separately.
        #
        # This avoids returning raw Neo4j Path objects.
        # ------------------------------------------------------

        relationship_query = f"""
        MATCH
            (start:Alert {{id: $alert_id}})
            -[relationships*1..{max_depth}]-
            (related)

        UNWIND relationships AS relationship

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
                "alert_id": normalized_alert_id,
            },
        )

        # ------------------------------------------------------
        # Serialize edges
        # ------------------------------------------------------

        edges: List[
            Dict[str, Any]
        ] = []

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

            if (
                source is None
                or target is None
                or relationship_type is None
            ):
                continue

            source_data = (
                serialize_node(
                    source
                )
            )

            target_data = (
                serialize_node(
                    target
                )
            )

            if (
                not source_data
                or not target_data
            ):
                continue

            source_id = source_data[
                "id"
            ]

            target_id = target_data[
                "id"
            ]

            relationship_type = str(
                relationship_type
            )

            # Ensure both nodes exist.
            node_map[
                source_id
            ] = source_data

            node_map[
                target_id
            ] = target_data

            # Prevent duplicate edges.
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
                    "relationship": (
                        relationship_type
                    ),
                    "type": "default",
                }
            )

        # ------------------------------------------------------
        # Final response
        # ------------------------------------------------------

        response = {
            "alert_id": normalized_alert_id,
            "nodes": list(
                node_map.values()
            ),
            "edges": edges,
        }

        if not edges:
            response["message"] = (
                "Alert exists but no related "
                "Neo4j relationships were found."
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
        """
        Find correlation paths from an alert.

        This method remains available for the existing
        LangGraph correlation pipeline.
        """

        try:
            alert_uuid = UUID(
                str(alert_id)
            )
            normalized_alert_id = str(
                alert_uuid
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            return []

        max_depth = max(
            1,
            min(
                int(max_depth),
                5,
            ),
        )

        results = await self._run(
            f"""
            MATCH path =
                (a:Alert {{id: $alert_id}})
                -[*1..{max_depth}]-
                (related)

            RETURN path
            """,
            {
                "alert_id": normalized_alert_id,
            },
        )

        return results

    async def find_attack_chains(
        self,
        asset_id: str,
    ) -> List[dict]:
        """Find attack patterns originating from an asset."""

        try:
            asset_uuid = UUID(
                str(asset_id)
            )
            normalized_asset_id = str(
                asset_uuid
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            return []

        results = await self._run(
            """
            MATCH
                (asset:Asset {id: $asset_id})
                <-[:TARGETS]-
                (alert:Alert)

            OPTIONAL MATCH
                (alert)-[:USES_TECHNIQUE]->
                (tech:Technique)

            OPTIONAL MATCH
                (alert)-[:CORRELATES_TO]->
                (inc:Incident)

            RETURN
                alert.id AS alert_id,
                alert.alert_type AS alert_type,
                alert.severity AS severity,
                collect(
                    DISTINCT tech.id
                ) AS techniques,
                collect(
                    DISTINCT inc.id
                ) AS incidents

            ORDER BY alert.severity DESC
            """,
            {
                "asset_id": normalized_asset_id,
            },
        )

        return results

    async def get_asset_blast_radius(
        self,
        asset_id: str,
    ) -> Dict[str, Any]:
        """Find assets reachable within two hops."""

        try:
            asset_uuid = UUID(
                str(asset_id)
            )
            normalized_asset_id = str(
                asset_uuid
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            return {
                "source_asset": str(
                    asset_id
                ),
                "blast_radius": [],
            }

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
                "asset_id": normalized_asset_id,
            },
        )

        return {
            "source_asset": normalized_asset_id,
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

        try:
            asset_uuid = UUID(
                str(asset_id)
            )
            normalized_asset_id = str(
                asset_uuid
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            return []

        try:
            limit = int(limit)
        except (
            ValueError,
            TypeError,
        ):
            limit = 50

        limit = max(
            1,
            min(limit, 500),
        )

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
                "asset_id": normalized_asset_id,
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
