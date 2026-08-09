"""BM25 search via PostgreSQL tsvector + GIN indexes."""
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text


class BM25Search:
    """BM25 text search using PostgreSQL tsvector columns and ts_rank_cd."""

    @staticmethod
    async def search_postmortems(
        db: AsyncSession, query: str, top_k: int = 20
    ) -> List[dict]:
        """BM25 search across postmortem summaries and root causes."""
        sql = text("""
            SELECT p.id, p.summary, p.root_cause, p.remediation, p.tags,
                   i.id as incident_id, i.title as incident_title,
                   ts_rank_cd(p.search_vector, plainto_tsquery(:query)) as bm25_score
            FROM postmortems p
            JOIN incidents i ON i.id = p.incident_id
            WHERE p.search_vector @@ plainto_tsquery(:query)
            ORDER BY bm25_score DESC
            LIMIT :limit
        """)
        result = await db.execute(sql, {"query": query, "limit": top_k})
        rows = result.mappings().all()
        return [dict(r) for r in rows]

    @staticmethod
    async def search_cves(
        db: AsyncSession, query: str, top_k: int = 20
    ) -> List[dict]:
        """BM25 search across CVE descriptions."""
        sql = text("""
            SELECT cr.id, cr.cve_id, cr.description, cr.cvss_score,
                   cr.affected_products, cr.published_date,
                   ts_rank_cd(cr.search_vector, plainto_tsquery(:query)) as bm25_score
            FROM cve_references cr
            WHERE cr.search_vector @@ plainto_tsquery(:query)
            ORDER BY bm25_score DESC
            LIMIT :limit
        """)
        result = await db.execute(sql, {"query": query, "limit": top_k})
        rows = result.mappings().all()
        return [dict(r) for r in rows]

    @staticmethod
    async def search_alerts(
        db: AsyncSession, query: str, top_k: int = 20
    ) -> List[dict]:
        """BM25 search across alert text fields."""
        sql = text("""
            SELECT a.id, a.source, a.alert_type, a.severity, a.status,
                   a.raw_alert, a.created_at,
                   ts_rank_cd(a.search_vector, plainto_tsquery(:query)) as bm25_score
            FROM alerts a
            WHERE a.search_vector @@ plainto_tsquery(:query)
            ORDER BY bm25_score DESC
            LIMIT :limit
        """)
        result = await db.execute(sql, {"query": query, "limit": top_k})
        rows = result.mappings().all()
        return [dict(r) for r in rows]

    @staticmethod
    async def update_tsvector(db: AsyncSession, table: str, record_id: str, text_content: str):
        """Update the tsvector column for a record after insert/update.

        Call this after inserting or updating a record to keep the
        tsvector column in sync for BM25 search.
        """
        sql = text(f"""
            UPDATE {table}
            SET search_vector = to_tsvector('english', :content)
            WHERE id = :id
        """)
        await db.execute(sql, {"content": text_content, "id": record_id})
        await db.commit()
