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

        IMPORTANT:
        This method intentionally uses result.data().
        Therefore callers should not assume that returned values
        are Neo4j Node/Relationship objects.

        Attack Replay queries explicitly request:
            labels(node)
            properties(node)
            relationship type
        instead of relying on Node object attributes.
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
        Synchronize one PostgreSQL alert and all related
        entities into Neo4j.
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

                # PostgreSQL INET can return IPv4Address /
                # IPv6Address. Neo4j receives a string.
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
        # 5. Load latest CorrelationResult
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
                    incident_result
                    .scalar_one_or_none()
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

        IMPORTANT:
        Do NOT return raw Neo4j Node objects from this method.

        Every node is converted inside Cypher into:

            {
                "id": "...",
                "labels": ["Alert"],
                "properties": {...}
            }

        Every edge is converted into:

            {
                "id": "...",
                "source": "...",
                "target": "...",
                "relationship": "TARGETS",
                "type": "default"
            }
        """

        # ------------------------------------------------------
        # 1. Normalize UUID
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
                "message": "Invalid alert UUID.",
            }

        normalized_alert_id = str(alert_uuid)

        # ------------------------------------------------------
        # 2. Limit traversal depth
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
        # 3. Check Alert node
        #
        # IMPORTANT:
        # We return scalar/map values instead of a Neo4j Node.
        # This completely avoids:
        #
        #     'dict' object has no attribute 'labels'
        #
        # ------------------------------------------------------

        check_query = """
        MATCH (start:Alert {id: $alert_id})

        RETURN
            start.id AS id,
            labels(start) AS labels,
            properties(start) AS properties
        """

        check_results = await self._run(
            check_query,
            {
                "alert_id": normalized_alert_id,
            },
        )

        if not check_results:
            return {
                "alert_id": normalized_alert_id,
                "nodes": [],
                "edges": [],
                "message": (
                    "Alert node not found in Neo4j. "
                    "The graph has not been synchronized yet."
                ),
            }

        start_record = check_results[0]

        # ------------------------------------------------------
        # 4. Node serializer
        #
        # This now accepts dictionaries only.
        # No .labels or .items() on Neo4j Node objects.
        # ------------------------------------------------------

        def serialize_node_record(
            node_id,
            labels,
            properties,
        ):
            if node_id is None:
                return None

            node_id = str(node_id)

            if labels is None:
                labels = []

            labels = [
                str(label)
                for label in labels
            ]

            if properties is None:
                properties = {}

            # Make sure properties is a dictionary.
            if not isinstance(properties, dict):
                try:
                    properties = dict(properties)
                except Exception:
                    properties = {}

            # --------------------------------------------------
            # Determine frontend node type
            # --------------------------------------------------

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

            # --------------------------------------------------
            # JSON-safe properties
            # --------------------------------------------------

            safe_properties = {}

            for key, value in properties.items():

                if value is None:
                    safe_properties[str(key)] = None

                elif isinstance(
                    value,
                    (
                        str,
                        int,
                        float,
                        bool,
                    ),
                ):
                    safe_properties[str(key)] = value

                elif isinstance(value, list):
                    safe_list = []

                    for item in value:
                        if item is None:
                            safe_list.append(None)

                        elif isinstance(
                            item,
                            (
                                str,
                                int,
                                float,
                                bool,
                            ),
                        ):
                            safe_list.append(item)

                        else:
                            safe_list.append(str(item))

                    safe_properties[str(key)] = safe_list

                elif isinstance(value, dict):
                    safe_properties[str(key)] = {
                        str(k): (
                            v
                            if isinstance(
                                v,
                                (
                                    str,
                                    int,
                                    float,
                                    bool,
                                ),
                            )
                            or v is None
                            else str(v)
                        )
                        for k, v in value.items()
                    }

                else:
                    safe_properties[str(key)] = str(value)

            return {
                "id": node_id,
                "type": node_type,
                "labels": labels,
                "properties": safe_properties,
            }

        # ------------------------------------------------------
        # 5. Initialize node map
        # ------------------------------------------------------

        node_map: Dict[
            str,
            Dict[str, Any],
        ] = {}

        start_node = serialize_node_record(
            start_record.get("id"),
            start_record.get("labels"),
            start_record.get("properties"),
        )

        if start_node:
            node_map[
                start_node["id"]
            ] = start_node

        # ------------------------------------------------------
        # 6. Retrieve connected nodes
        #
        # Again, return scalar/map values rather than Neo4j
        # Node objects.
        # ------------------------------------------------------

        related_query = f"""
        MATCH
            (start:Alert {{id: $alert_id}})
            -[*1..{max_depth}]-
            (related)

        WITH DISTINCT related

        RETURN
            related.id AS id,
            labels(related) AS labels,
            properties(related) AS properties
        """

        related_results = await self._run(
            related_query,
            {
                "alert_id": normalized_alert_id,
            },
        )

        for row in related_results:

            serialized = serialize_node_record(
                row.get("id"),
                row.get("labels"),
                row.get("properties"),
            )

            if serialized:
                node_map[
                    serialized["id"]
                ] = serialized

        # ------------------------------------------------------
        # 7. Retrieve relationships
        #
        # We explicitly return:
        #
        #   startNode(relationship).id
        #   type(relationship)
        #   endNode(relationship).id
        #
        # instead of returning Neo4j objects.
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
            source.id AS source_id,
            labels(source) AS source_labels,
            properties(source) AS source_properties,

            type(relationship) AS relationship_type,

            target.id AS target_id,
            labels(target) AS target_labels,
            properties(target) AS target_properties
        """

        relationship_rows = await self._run(
            relationship_query,
            {
                "alert_id": normalized_alert_id,
            },
        )

        # ------------------------------------------------------
        # 8. Serialize edges
        # ------------------------------------------------------

        edges: List[
            Dict[str, Any]
        ] = []

        edge_seen = set()

        for row in relationship_rows:

            source_id = row.get(
                "source_id"
            )

            target_id = row.get(
                "target_id"
            )

            relationship_type = row.get(
                "relationship_type"
            )

            if (
                source_id is None
                or target_id is None
                or relationship_type is None
            ):
                continue

            source_node = serialize_node_record(
                source_id,
                row.get("source_labels"),
                row.get("source_properties"),
            )

            target_node = serialize_node_record(
                target_id,
                row.get("target_labels"),
                row.get("target_properties"),
            )

            if (
                not source_node
                or not target_node
            ):
                continue

            source_id = source_node["id"]
            target_id = target_node["id"]
            relationship_type = str(
                relationship_type
            )

            # Ensure both nodes exist.
            node_map[
                source_id
            ] = source_node

            node_map[
                target_id
            ] = target_node

            # Prevent duplicate edges.
            edge_key = (
                source_id,
                relationship_type,
                target_id,
            )

            if edge_key in edge_seen:
                continue

            edge_seen.add(edge_key)

            edges.append(
                {
                    "id": (
                        f"{source_id}-"
                        f"{relationship_type}-"
                        f"{target_id}"
                    ),
                    "source": source_id,
                    "target": target_id,
                    "relationship": relationship_type,
                    "type": "default",
                }
            )

        # ------------------------------------------------------
        # 9. Final response
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
