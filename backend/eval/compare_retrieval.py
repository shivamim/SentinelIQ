"""Retrieval strategy comparison: BM25-only vs Vector-only vs Hybrid (RRF) vs Hybrid+Rerank.

Runs the same queries from rag_dataset.json through four retrieval strategies
and compares Recall@K, MRR, and NDCG for each.

Supports gold-labeled relevant IDs when available. Falls back to keyword-based
estimation for unlabeled questions, clearly marking them.

Usage:
    python -m eval.compare_retrieval
    python -m eval.compare_retrieval --top-k 20 --dataset eval/rag_dataset.json
"""
import argparse
import asyncio
import json
import math
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

# Ensure project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database import AsyncSessionLocal
from app.services.embeddings import embedding_service
from app.graph.retrieval import HybridRetrieval, CohereReranker, RRF_K
from app.config import get_settings

settings = get_settings()


# ─── Metric implementations ────────────────────────────────────────────────

def recall_at_k(retrieved: List[Dict], relevant: Set[str], k: int) -> float:
    if not relevant:
        return 0.0
    ids = {str(d.get("id", d.get("chunk_id", ""))) for d in retrieved[:k]}
    return len(relevant & ids) / len(relevant)


def reciprocal_rank(retrieved: List[Dict], relevant: Set[str]) -> float:
    for rank, doc in enumerate(retrieved, start=1):
        if str(doc.get("id", doc.get("chunk_id", ""))) in relevant:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(retrieved: List[Dict], relevant: Set[str], k: int) -> float:
    """NDCG@K with binary relevance."""
    dcg = 0.0
    for i, doc in enumerate(retrieved[:k], start=1):
        doc_id = str(doc.get("id", doc.get("chunk_id", "")))
        rel = 1.0 if doc_id in relevant else 0.0
        dcg += rel / math.log2(i + 1)
    num_relevant_in_k = min(len(relevant), k)
    idcg = 0.0
    for i in range(1, num_relevant_in_k + 1):
        idcg += 1.0 / math.log2(i + 1)
    if idcg == 0.0:
        return 0.0
    return dcg / idcg


def get_relevant_ids(
    entry: Dict[str, Any],
    results: List[Dict],
) -> tuple[Set[str], bool]:
    """Get relevant IDs for a question, preferring gold labels over estimation."""
    gold_chunk_ids = entry.get("relevant_chunk_ids", [])
    gold_doc_ids = entry.get("relevant_document_ids", [])

    if gold_chunk_ids:
        return set(str(cid) for cid in gold_chunk_ids), True
    if gold_doc_ids:
        return set(str(did) for did in gold_doc_ids), True

    # Fallback: keyword estimation
    expected_types = entry.get("expected_document_types", [])
    expected_kws = entry.get("expected_keywords", [])
    estimated = estimate_relevant_ids(results, expected_kws, expected_types)
    return estimated, False


def estimate_relevant_ids(
    results: List[Dict],
    expected_keywords: List[str],
    expected_document_types: List[str],
) -> Set[str]:
    """Estimate relevant IDs from results based on keyword + type match."""
    relevant = set()
    for doc in results:
        doc_type = doc.get("document_type", "")
        if doc_type not in expected_document_types:
            continue
        chunk_text = doc.get("chunk_text", "").lower()
        for kw in expected_keywords:
            if kw.lower() in chunk_text:
                relevant.add(str(doc.get("id", doc.get("chunk_id", ""))))
                break
    return relevant


# ─── Strategy 1: BM25 only ─────────────────────────────────────────────────

async def search_bm25_only(
    db: AsyncSession,
    query: str,
    top_k: int,
    filters: Dict[str, Any] = None,
) -> List[Dict]:
    """BM25 search using tsvector on document_chunks."""
    where_clauses = []
    params: Dict[str, Any] = {"query": query, "limit": top_k}

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

    where_sql = ""
    if where_clauses:
        where_sql = "AND " + " AND ".join(where_clauses)

    sql = text(f"""
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
    result = await db.execute(sql, params)
    return [dict(r) for r in result.mappings().all()]


# ─── Strategy 2: Vector only ───────────────────────────────────────────────

async def search_vector_only(
    db: AsyncSession,
    query: str,
    query_embedding: List[float],
    top_k: int,
    filters: Dict[str, Any] = None,
) -> List[Dict]:
    """Vector search using pgvector cosine on document_chunks."""
    where_clauses = []
    params: Dict[str, Any] = {"embedding": str(query_embedding), "limit": top_k}

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

    where_sql = ""
    if where_clauses:
        where_sql = "AND " + " AND ".join(where_clauses)

    sql = text(f"""
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
    result = await db.execute(sql, params)
    return [dict(r) for r in result.mappings().all()]


# ─── Strategy 3: BM25 + Vector + RRF (hybrid, no reranker) ────────────────

async def search_hybrid_rrf(
    db: AsyncSession,
    query: str,
    query_embedding: List[float],
    top_k: int,
    filters: Dict[str, Any] = None,
) -> List[Dict]:
    """Hybrid BM25 + Vector with RRF fusion, no reranking."""
    bm25_results = await search_bm25_only(db, query, top_k, filters)
    vector_results = await search_vector_only(db, query, query_embedding, top_k, filters)
    fused = HybridRetrieval._reciprocal_rank_fusion(
        bm25_results, vector_results, top_n=top_k
    )
    return fused


# ─── Strategy 4: BM25 + Vector + RRF + Cohere Reranker ────────────────────

async def search_hybrid_reranked(
    db: AsyncSession,
    query: str,
    query_embedding: List[float],
    top_k: int,
    filters: Dict[str, Any] = None,
) -> Tuple[List[Dict], str]:
    """Hybrid BM25 + Vector with RRF fusion + Cohere reranker.

    Returns (results, reranker_status).
    """
    fused = await search_hybrid_rrf(db, query, query_embedding, top_k, filters)
    reranked, reranker_status = await CohereReranker.rerank_with_status(
        query, fused, top_n=min(5, top_k)
    )
    return reranked, reranker_status


# ─── Evaluation runner ─────────────────────────────────────────────────────

STRATEGIES = {
    "BM25 Only": search_bm25_only,
    "Vector Only": None,  # handled specially (needs embedding)
    "Hybrid (RRF)": None,  # handled specially
    "Hybrid+Rerank": None,  # handled specially
}


async def run_strategy(
    strategy_name: str,
    db: AsyncSession,
    query: str,
    query_embedding: List[float],
    top_k: int,
) -> Tuple[List[Dict], str]:
    """Run a single retrieval strategy.

    Returns (results, reranker_status).
    """
    if strategy_name == "BM25 Only":
        results = await search_bm25_only(db, query, top_k)
        return results, "skipped"
    elif strategy_name == "Vector Only":
        results = await search_vector_only(db, query, query_embedding, top_k)
        return results, "skipped"
    elif strategy_name == "Hybrid (RRF)":
        results = await search_hybrid_rrf(db, query, query_embedding, top_k)
        return results, "skipped"
    elif strategy_name == "Hybrid+Rerank":
        results, reranker_status = await search_hybrid_reranked(db, query, query_embedding, top_k)
        return results, reranker_status
    else:
        raise ValueError(f"Unknown strategy: {strategy_name}")


async def run_comparison(dataset_path: str, top_k: int) -> None:
    """Load dataset, run all strategies for each question, compare."""
    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    strategy_names = [
        "BM25 Only",
        "Vector Only",
        "Hybrid (RRF)",
        "Hybrid+Rerank",
    ]

    gold_count = sum(1 for e in dataset if e.get("relevant_chunk_ids") or e.get("relevant_document_ids"))
    estimated_count = len(dataset) - gold_count

    print(f"\n{'='*90}")
    print(f"Retrieval Strategy Comparison — {len(dataset)} questions, top_k={top_k}")
    print(f"Gold-labeled: {gold_count} | Estimated: {estimated_count}")
    if estimated_count > 0:
        print(f"⚠ {estimated_count} questions have no gold labels — metrics are estimated")
    print(f"{'='*90}\n")

    # Results: {strategy_name: [{question, recall, mrr, ndcg, ...}, ...]}
    all_results: Dict[str, List[Dict]] = {name: [] for name in strategy_names}

    async with AsyncSessionLocal() as db:
        for i, entry in enumerate(dataset):
            question = entry["question"]

            print(f"[{i+1}/{len(dataset)}] {question[:70]}...")

            # Compute query embedding (reuse across strategies)
            try:
                query_embedding = await asyncio.to_thread(
                    embedding_service.embed, [question]
                )
                query_embedding = query_embedding[0]
            except Exception as exc:
                print(f"    ✗ Embedding failed: {exc}")
                for name in strategy_names:
                    all_results[name].append({
                        "question": question,
                        "recall_at_k": 0.0,
                        "mrr": 0.0,
                        "ndcg_at_k": 0.0,
                        "results_count": 0,
                        "error": str(exc),
                    })
                continue

            for name in strategy_names:
                try:
                    results, reranker_status = await run_strategy(
                        name, db, question, query_embedding, top_k
                    )
                except Exception as exc:
                    all_results[name].append({
                        "question": question,
                        "recall_at_k": 0.0,
                        "mrr": 0.0,
                        "ndcg_at_k": 0.0,
                        "results_count": 0,
                        "reranker_status": "error",
                        "error": str(exc),
                    })
                    continue

                # Get relevant IDs — gold labels preferred
                relevant_ids, is_gold = get_relevant_ids(entry, results)
                r_at_k = recall_at_k(results, relevant_ids, top_k)
                mrr_val = reciprocal_rank(results, relevant_ids)
                ndcg_val = ndcg_at_k(results, relevant_ids, top_k)

                all_results[name].append({
                    "question": question,
                    "recall_at_k": r_at_k,
                    "mrr": mrr_val,
                    "ndcg_at_k": ndcg_val,
                    "results_count": len(results),
                    "relevant_count": len(relevant_ids),
                    "gold_labeled": is_gold,
                    "reranker_status": reranker_status,
                    "error": None,
                })

            # Print per-question summary
            summary_parts = []
            for name in strategy_names:
                last = all_results[name][-1]
                summary_parts.append(f"{name}: R={last['recall_at_k']:.2f} M={last['mrr']:.2f}")
            print(f"    {' | '.join(summary_parts)}")

    # ── Comparison Table ────────────────────────────────────────────────
    print(f"\n{'═'*90}")
    print("Comparison Table")
    print(f"{'═'*90}")
    header = f"{'Strategy':<20}  {'Avg Recall@K':>13}  {'Avg MRR':>8}  {'Avg NDCG':>9}  {'Avg Results':>12}  {'Errors':>7}"
    print(header)
    print(f"{'─'*90}")

    for name in strategy_names:
        valid = [r for r in all_results[name] if r["error"] is None]
        errors = [r for r in all_results[name] if r["error"] is not None]

        if valid:
            avg_recall = sum(r["recall_at_k"] for r in valid) / len(valid)
            avg_mrr = sum(r["mrr"] for r in valid) / len(valid)
            avg_ndcg = sum(r.get("ndcg_at_k", 0.0) for r in valid) / len(valid)
            avg_results = sum(r["results_count"] for r in valid) / len(valid)
        else:
            avg_recall = 0.0
            avg_mrr = 0.0
            avg_ndcg = 0.0
            avg_results = 0.0

        print(f"{name:<20}  {avg_recall:>13.4f}  {avg_mrr:>8.4f}  {avg_ndcg:>9.4f}  {avg_results:>12.1f}  {len(errors):>7}")

    # ── Reranker status summary ────────────────────────────────────────
    reranked_results = all_results.get("Hybrid+Rerank", [])
    if reranked_results:
        status_counts = {}
        for r in reranked_results:
            s = r.get("reranker_status", "unknown")
            status_counts[s] = status_counts.get(s, 0) + 1
        print(f"\n  Reranker status distribution (Hybrid+Rerank): {status_counts}")

    # ── Per-category breakdown ──────────────────────────────────────────
    categories = sorted(set(
        entry.get("category", "unknown") for entry in dataset
    ))
    print(f"\n{'═'*90}")
    print("Per-Category Comparison")
    print(f"{'═'*90}")

    for cat in categories:
        cat_indices = [i for i, e in enumerate(dataset) if e.get("category") == cat]
        if not cat_indices:
            continue
        print(f"\n  Category: {cat} ({len(cat_indices)} questions)")
        print(f"  {'Strategy':<20}  {'Avg Recall@K':>13}  {'Avg MRR':>8}  {'Avg NDCG':>9}")
        print(f"  {'─'*60}")
        for name in strategy_names:
            cat_results = [all_results[name][i] for i in cat_indices if i < len(all_results[name])]
            valid = [r for r in cat_results if r["error"] is None]
            if valid:
                avg_recall = sum(r["recall_at_k"] for r in valid) / len(valid)
                avg_mrr = sum(r["mrr"] for r in valid) / len(valid)
                avg_ndcg = sum(r.get("ndcg_at_k", 0.0) for r in valid) / len(valid)
            else:
                avg_recall = 0.0
                avg_mrr = 0.0
                avg_ndcg = 0.0
            print(f"  {name:<20}  {avg_recall:>13.4f}  {avg_mrr:>8.4f}  {avg_ndcg:>9.4f}")

    # Save results
    output_path = Path(dataset_path).parent / "retrieval_comparison_results.json"
    summary = {}
    for name in strategy_names:
        valid = [r for r in all_results[name] if r["error"] is None]
        summary[name] = {
            "avg_recall_at_k": sum(r["recall_at_k"] for r in valid) / len(valid) if valid else 0.0,
            "avg_mrr": sum(r["mrr"] for r in valid) / len(valid) if valid else 0.0,
            "avg_ndcg_at_k": sum(r.get("ndcg_at_k", 0.0) for r in valid) / len(valid) if valid else 0.0,
            "questions_evaluated": len(valid),
            "questions_total": len(all_results[name]),
        }
    with open(output_path, "w") as f:
        json.dump({
            "top_k": top_k,
            "dataset": str(dataset_path),
            "gold_labeled_count": gold_count,
            "estimated_count": estimated_count,
            "strategies": summary,
            "per_question": {name: results for name, results in all_results.items()},
        }, f, indent=2)
    print(f"\nResults saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Compare retrieval strategies")
    parser.add_argument(
        "--top-k", type=int, default=20,
        help="Number of chunks to retrieve (default: 20)",
    )
    parser.add_argument(
        "--dataset", type=str,
        default=str(Path(__file__).resolve().parent / "rag_dataset.json"),
        help="Path to RAG evaluation dataset JSON",
    )
    args = parser.parse_args()

    asyncio.run(run_comparison(args.dataset, args.top_k))


if __name__ == "__main__":
    main()
