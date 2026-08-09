"""Retrieval layer: BM25 + Vector + Reciprocal Rank Fusion + optional Cohere reranker."""
import asyncio
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select
from app.models import (
    Alert,
    Incident,
    Asset,
    CveEmbedding,
    PostmortemEmbedding,
    MitreTechniqueEmbedding,
    CveReference,
)
from app.services.embeddings import embedding_service
from app.services.bm25 import BM25Search
from app.config import get_settings

settings = get_settings()

# RRF constant
RRF_K = 60


class StructuredRetrieval:
    """Text-to-SQL style structured history lookup."""

    @staticmethod
    async def asset_context(db: AsyncSession, asset_id: str) -> Optional[dict]:
        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return None
        return {
            "id": str(asset.id),
            "hostname": asset.hostname,
            "ip_address": str(asset.ip_address) if asset.ip_address else None,
            "asset_type": asset.asset_type,
            "criticality": asset.criticality,
            "owner_team": asset.owner_team,
            "environment": asset.environment,
        }

    @staticmethod
    async def history_by_ioc(
        db: AsyncSession,
        ioc_ip: Optional[str] = None,
        ioc_domain: Optional[str] = None,
        ioc_hash: Optional[str] = None,
        asset_id: Optional[str] = None,
        alert_type: Optional[str] = None,
    ) -> List[dict]:
        """Find past alerts/incidents matching IOC or asset+alert_type combo."""
        conditions = []
        params = {}
        if ioc_ip:
            conditions.append("ioc_ip = :ioc_ip")
            params["ioc_ip"] = ioc_ip
        if ioc_domain:
            conditions.append("ioc_domain = :ioc_domain")
            params["ioc_domain"] = ioc_domain
        if ioc_hash:
            conditions.append("ioc_hash = :ioc_hash")
            params["ioc_hash"] = ioc_hash
        if asset_id and alert_type:
            conditions.append("asset_id = :asset_id AND alert_type = :alert_type")
            params["asset_id"] = asset_id
            params["alert_type"] = alert_type

        if not conditions:
            return []

        where_clause = " OR ".join(conditions)
        sql = text(f"""
            SELECT a.id, a.source, a.alert_type, a.severity, a.status, a.created_at,
                   a.raw_alert,
                   i.id as incident_id, i.title as incident_title, i.severity as incident_severity
            FROM alerts a
            LEFT JOIN incidents i ON i.id = (
                SELECT incident_id FROM postmortems pm
                JOIN postmortem_embeddings pme ON pme.postmortem_id = pm.id
                LIMIT 1
            )
            WHERE {where_clause}
            ORDER BY a.created_at DESC
            LIMIT 20
        """)
        result = await db.execute(sql, params)
        rows = result.mappings().all()
        return [dict(r) for r in rows]


class HybridRetrieval:
    """BM25 + Vector search with Reciprocal Rank Fusion.

    Pipeline:
    1. BM25 search via tsvector (top 20 each)
    2. Vector search via pgvector cosine (top 20 each)
    3. Reciprocal Rank Fusion to merge: RRF_score(d) = Σ 1/(k + rank_i)
    4. Optional Cohere reranker on top-10 RRF results
    """

    @staticmethod
    def _reciprocal_rank_fusion(
        *ranked_lists: List[dict],
        k: int = RRF_K,
        top_n: int = 10,
    ) -> List[dict]:
        """Merge multiple ranked lists using Reciprocal Rank Fusion.

        Each list item must have a unique 'id' or 'cve_id' key for dedup.
        """
        rrf_scores: Dict[str, float] = {}
        doc_map: Dict[str, dict] = {}

        for ranked_list in ranked_lists:
            for rank, doc in enumerate(ranked_list, start=1):
                doc_key = str(doc.get("id") or doc.get("cve_id") or doc.get("postmortem_id", ""))
                if not doc_key:
                    continue
                rrf_scores[doc_key] = rrf_scores.get(doc_key, 0.0) + 1.0 / (k + rank)
                if doc_key not in doc_map:
                    doc_map[doc_key] = doc

        # Sort by RRF score descending
        sorted_keys = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
        result = []
        for key in sorted_keys[:top_n]:
            doc = doc_map[key].copy()
            doc["rrf_score"] = rrf_scores[key]
            result.append(doc)
        return result

    @staticmethod
    async def search_cves(
        db: AsyncSession, query: str, query_embedding: List[float], top_k: int = 20
    ) -> List[dict]:
        """Hybrid BM25 + vector search for CVEs, fused with RRF."""
        # 1. BM25 search
        bm25_results = await BM25Search.search_cves(db, query, top_k=top_k)

        # 2. Vector search
        sql = text("""
            SELECT ce.id, ce.cve_id, ce.chunk_text, cr.cvss_score, cr.description,
                   1 - (ce.embedding <=> :embedding) as similarity
            FROM cve_embeddings ce
            JOIN cve_references cr ON cr.cve_id = ce.cve_id
            ORDER BY ce.embedding <=> :embedding
            LIMIT :limit
        """)
        result = await db.execute(sql, {"embedding": str(query_embedding), "limit": top_k})
        vector_results = [dict(r) for r in result.mappings().all()]

        # 3. Reciprocal Rank Fusion
        fused = HybridRetrieval._reciprocal_rank_fusion(bm25_results, vector_results, top_n=10)

        # 4. Optional Cohere reranker
        if settings.COHERE_API_KEY:
            fused = await CohereReranker.rerank(query, fused, top_n=5)

        return fused

    @staticmethod
    async def search_postmortems(
        db: AsyncSession, query: str, query_embedding: List[float], top_k: int = 20
    ) -> List[dict]:
        """Hybrid BM25 + vector search for postmortems, fused with RRF."""
        # 1. BM25 search
        bm25_results = await BM25Search.search_postmortems(db, query, top_k=top_k)

        # 2. Vector search
        sql = text("""
            SELECT pe.id, pe.postmortem_id, pe.chunk_text,
                   1 - (pe.embedding <=> :embedding) as similarity
            FROM postmortem_embeddings pe
            ORDER BY pe.embedding <=> :embedding
            LIMIT :limit
        """)
        result = await db.execute(sql, {"embedding": str(query_embedding), "limit": top_k})
        vector_results = [dict(r) for r in result.mappings().all()]

        # 3. Reciprocal Rank Fusion
        fused = HybridRetrieval._reciprocal_rank_fusion(bm25_results, vector_results, top_n=10)

        # 4. Optional Cohere reranker
        if settings.COHERE_API_KEY:
            fused = await CohereReranker.rerank(query, fused, top_n=5)

        return fused

    @staticmethod
    async def search_mitre(
        db: AsyncSession, query_embedding: List[float], top_k: int = 5
    ) -> List[dict]:
        """Vector search over MITRE ATT&CK technique embeddings."""
        sql = text("""
            SELECT id, technique_id, chunk_text,
                   1 - (embedding <=> :embedding) as similarity
            FROM mitre_technique_embeddings
            ORDER BY embedding <=> :embedding
            LIMIT :limit
        """)
        result = await db.execute(sql, {"embedding": str(query_embedding), "limit": top_k})
        rows = result.mappings().all()
        return [dict(r) for r in rows]

    @staticmethod
    async def search_documents(
        db: AsyncSession,
        query: str,
        query_embedding: List[float],
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 20,
    ) -> List[dict]:
        """Hybrid BM25 + vector search over document_chunks with metadata filtering.

        Supports filtering by:
        - document_type: exact match on documents.document_type
        - source: exact match on documents.source
        - technique_id: JSON metadata containment check
        - cve_id: JSON metadata containment check
        - severity: JSON metadata containment check
        - asset: JSON metadata containment check

        Returns fused results with document metadata joined.
        """
        # Build WHERE clause from filters
        where_clauses = []
        params: Dict[str, Any] = {"query": query, "limit": top_k, "embedding": str(query_embedding)}

        if filters:
            if "document_type" in filters:
                dt = filters["document_type"]
                if isinstance(dt, list):
                    placeholders = ", ".join(f":dt_{i}" for i in range(len(dt)))
                    where_clauses.append(f"d.document_type IN ({placeholders})")
                    for i, v in enumerate(dt):
                        params[f"dt_{i}"] = v
                else:
                    where_clauses.append("d.document_type = :dt")
                    params["dt"] = dt

            if "source" in filters:
                src = filters["source"]
                if isinstance(src, list):
                    placeholders = ", ".join(f":src_{i}" for i in range(len(src)))
                    where_clauses.append(f"d.source IN ({placeholders})")
                    for i, v in enumerate(src):
                        params[f"src_{i}"] = v
                else:
                    where_clauses.append("d.source = :src")
                    params["src"] = src

            # JSON metadata containment filters
            for meta_key in ("technique_id", "cve_id", "severity", "asset"):
                if meta_key in filters:
                    val = filters[meta_key]
                    if isinstance(val, list):
                        # Check if any value in the list matches metadata
                        or_conditions = []
                        for i, v in enumerate(val):
                            param_name = f"{meta_key}_{i}"
                            or_conditions.append(f"dc.metadata @> jsonb_build_object('{meta_key}', :{param_name})")
                            params[param_name] = v
                        where_clauses.append(f"({' OR '.join(or_conditions)})")
                    else:
                        where_clauses.append(f"dc.metadata @> jsonb_build_object('{meta_key}', :{meta_key})")
                        params[meta_key] = val

        where_sql = ""
        if where_clauses:
            where_sql = "AND " + " AND ".join(where_clauses)

        # 1. BM25 search on document_chunks using tsvector
        bm25_sql = text(f"""
            SELECT dc.id, dc.document_id, dc.chunk_index, dc.chunk_text, dc.metadata,
                   d.title as document_title, d.source as document_source, d.document_type,
                   ts_rank_cd(dc.search_vector, plainto_tsquery(:query)) as bm25_score
            FROM document_chunks dc
            JOIN documents d ON d.id = dc.document_id
            WHERE dc.search_vector @@ plainto_tsquery(:query)
            {where_sql}
            ORDER BY bm25_score DESC
            LIMIT :limit
        """)
        bm25_result = await db.execute(bm25_sql, params)
        bm25_results = [dict(r) for r in bm25_result.mappings().all()]

        # 2. Vector search on document_chunks using pgvector cosine distance
        vector_sql = text(f"""
            SELECT dc.id, dc.document_id, dc.chunk_index, dc.chunk_text, dc.metadata,
                   d.title as document_title, d.source as document_source, d.document_type,
                   1 - (dc.embedding <=> :embedding) as similarity
            FROM document_chunks dc
            JOIN documents d ON d.id = dc.document_id
            WHERE dc.embedding IS NOT NULL
            {where_sql}
            ORDER BY dc.embedding <=> :embedding
            LIMIT :limit
        """)
        vector_result = await db.execute(vector_sql, params)
        vector_results = [dict(r) for r in vector_result.mappings().all()]

        # 3. Reciprocal Rank Fusion
        fused = HybridRetrieval._reciprocal_rank_fusion(
            bm25_results, vector_results, top_n=top_k
        )

        return fused


class CohereReranker:
    """Optional second-stage Cohere reranker (NOT the primary retrieval strategy).

    Always returns reranker_status: "success", "skipped", or "failed".
    """

    @staticmethod
    async def rerank(query: str, documents: List[dict], top_n: int = 5) -> List[dict]:
        """Rerank documents — backward-compatible wrapper (no status returned)."""
        results, _ = await CohereReranker.rerank_with_status(query, documents, top_n)
        return results

    @staticmethod
    async def rerank_with_status(
        query: str, documents: List[dict], top_n: int = 5
    ) -> tuple[List[dict], str]:
        """Rerank documents and return (results, reranker_status).

        Returns:
            Tuple of (reranked_documents, status_string)
            status_string is one of: "success", "skipped", "failed"
        """
        if not documents or not settings.COHERE_API_KEY:
            return documents[:top_n], "skipped"
        try:
            import cohere

            def _sync_rerank():
                client = cohere.Client(settings.COHERE_API_KEY)
                texts = [d.get("chunk_text", d.get("summary", d.get("description", str(d)))) for d in documents]
                response = client.rerank(
                    model=settings.RERANKER_MODEL,
                    query=query,
                    documents=texts,
                    top_n=top_n,
                )
                ranked = []
                for r in response.results:
                    doc = documents[r.index].copy()
                    doc["rerank_score"] = r.relevance_score
                    ranked.append(doc)
                return ranked

            result = await asyncio.to_thread(_sync_rerank)
            return result, "success"
        except Exception:
            # Reranker is optional — if it fails, return RRF results as-is
            # But we report the failure status so callers know reranking didn't happen
            return documents[:top_n], "failed"
