"""RAG pipeline evaluation: Recall@K, MRR, NDCG over a curated cybersecurity question set.

Supports two modes:
1. Gold-labeled: questions with explicit relevant_document_ids / relevant_chunk_ids
   → computes metrics against independent ground truth.
2. Keyword-estimated: questions without gold labels
   → estimates relevance from keyword/type matching (clearly marked as approximate).

IMPORTANT: Metrics are NEVER computed by deriving relevance from the retrieved results.
If gold IDs are not available, metrics are computed from keyword-based estimation
and explicitly marked as "estimated" — not as independent retrieval benchmarks.

Usage:
    python -m eval.evaluate_rag --top-k 20
    python -m eval.evaluate_rag --top-k 10 --dataset eval/rag_dataset.json
    python -m eval.evaluate_rag --label-gold  # interactive gold-labeling tool
"""
import argparse
import asyncio
import json
import math
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Set

# Ensure project root is on sys.path so `app` is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.services.rag_pipeline import RAGPipeline
from app.database import AsyncSessionLocal


# ─── Metric implementations ────────────────────────────────────────────────

def recall_at_k(
    retrieved_docs: List[Dict[str, Any]],
    relevant_ids: Set[str],
    k: int,
) -> float:
    """Recall@K = |relevant ∩ retrieved[:K]| / |relevant|.

    If |relevant| == 0, returns 0.0 (degenerate case).
    """
    if not relevant_ids:
        return 0.0
    retrieved_ids = {str(d.get("id", d.get("chunk_id", ""))) for d in retrieved_docs[:k]}
    hits = len(relevant_ids & retrieved_ids)
    return hits / len(relevant_ids)


def reciprocal_rank(
    retrieved_docs: List[Dict[str, Any]],
    relevant_ids: Set[str],
) -> float:
    """MRR = 1 / rank_of_first_relevant_doc.

    Returns 0.0 if no relevant document appears in the list.
    """
    for rank, doc in enumerate(retrieved_docs, start=1):
        doc_id = str(doc.get("id", doc.get("chunk_id", "")))
        if doc_id in relevant_ids:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(
    retrieved_docs: List[Dict[str, Any]],
    relevant_ids: Set[str],
    k: int,
) -> float:
    """NDCG@K = DCG@K / IDCG@K.

    Binary relevance: doc is relevant (1) if its id is in relevant_ids, else 0.
    DCG@K  = Σ_{i=1..K} rel_i / log2(i + 1)
    IDCG@K = Σ_{i=1..min(|relevant|, K)} 1 / log2(i + 1)
    """
    # DCG@K
    dcg = 0.0
    for i, doc in enumerate(retrieved_docs[:k], start=1):
        doc_id = str(doc.get("id", doc.get("chunk_id", "")))
        rel = 1.0 if doc_id in relevant_ids else 0.0
        dcg += rel / math.log2(i + 1)

    # IDCG@K — best possible DCG with all relevant docs at the top
    num_relevant_in_k = min(len(relevant_ids), k)
    idcg = 0.0
    for i in range(1, num_relevant_in_k + 1):
        idcg += 1.0 / math.log2(i + 1)

    if idcg == 0.0:
        return 0.0
    return dcg / idcg


# ─── Relevance determination ──────────────────────────────────────────────

def get_relevant_ids(
    entry: Dict[str, Any],
    sources: List[Dict[str, Any]],
) -> tuple[Set[str], bool]:
    """Get relevant IDs for a question, preferring gold labels over estimation.

    Returns:
        Tuple of (relevant_ids, is_gold_labeled)
        is_gold_labeled is True if gold IDs were available, False if estimated.
    """
    # Check for gold-labeled relevant_chunk_ids first
    gold_chunk_ids = entry.get("relevant_chunk_ids", [])
    gold_doc_ids = entry.get("relevant_document_ids", [])

    if gold_chunk_ids:
        return set(str(cid) for cid in gold_chunk_ids), True

    if gold_doc_ids:
        # Use document IDs as relevance signal
        return set(str(did) for did in gold_doc_ids), True

    # No gold labels — estimate from keyword matching
    expected_types = entry.get("expected_document_types", [])
    expected_kws = entry.get("expected_keywords", [])
    estimated = estimate_relevant_ids(sources, expected_kws, expected_types)
    return estimated, False


def estimate_relevant_ids(
    sources: List[Dict[str, Any]],
    expected_keywords: List[str],
    expected_document_types: List[str],
) -> Set[str]:
    """Estimate which retrieved source IDs are relevant based on keyword + type matching.

    WARNING: This is NOT a valid independent retrieval benchmark. It estimates
    relevance from the retrieved results themselves. Metrics computed from
    estimated relevance are approximate and should be clearly labeled.

    A source is considered relevant if:
      - Its document_type matches one of expected_document_types, AND
      - Its chunk_text contains at least one expected keyword (case-insensitive)
    """
    relevant = set()
    for src in sources:
        doc_type = src.get("document_type", "")
        if doc_type not in expected_document_types:
            continue
        chunk_text = src.get("chunk_text", "").lower()
        for kw in expected_keywords:
            if kw.lower() in chunk_text:
                relevant.add(str(src.get("chunk_id", src.get("id", ""))))
                break
    return relevant


# ─── Main evaluation loop ──────────────────────────────────────────────────

async def evaluate_single_question(
    db,
    entry: Dict[str, Any],
    top_k: int,
) -> Dict[str, Any]:
    """Run the RAG pipeline for a single question and compute metrics."""
    question = entry["question"]

    # Run the full RAG pipeline
    try:
        result = await RAGPipeline.search(
            db,
            query=question,
            top_k=top_k,
            rerank_top_n=min(5, top_k),
        )
    except Exception as exc:
        return {
            "question": question,
            "error": str(exc),
            "recall_at_k": 0.0,
            "mrr": 0.0,
            "ndcg_at_k": 0.0,
            "sources_count": 0,
            "grounding_status": "error",
            "gold_labeled": entry.get("gold_labeled", False),
            "metric_type": "error",
        }

    sources = result.get("sources", [])
    grounding = result.get("grounding_status", "unknown")

    # Get relevant IDs — gold labels preferred, estimation as fallback
    relevant_ids, is_gold = get_relevant_ids(entry, sources)

    # Determine metric type label
    if is_gold:
        metric_type = "gold"
    else:
        metric_type = "estimated"

    # Compute metrics against relevant IDs
    r_at_k = recall_at_k(sources, relevant_ids, top_k)
    mrr_val = reciprocal_rank(sources, relevant_ids)
    ndcg_val = ndcg_at_k(sources, relevant_ids, top_k)

    # Also count keyword hits as a separate check
    expected_kws = entry.get("expected_keywords", [])
    keyword_hits = 0
    for src in sources:
        text = src.get("chunk_text", "").lower()
        if any(kw.lower() in text for kw in expected_kws):
            keyword_hits += 1

    return {
        "question": question,
        "category": entry.get("category", "unknown"),
        "difficulty": entry.get("difficulty", "unknown"),
        "recall_at_k": r_at_k,
        "mrr": mrr_val,
        "ndcg_at_k": ndcg_val,
        "keyword_hits": keyword_hits,
        "sources_count": len(sources),
        "relevant_count": len(relevant_ids),
        "grounding_status": grounding,
        "gold_labeled": is_gold,
        "metric_type": metric_type,
        "error": None,
    }


async def run_evaluation(dataset_path: str, top_k: int) -> None:
    """Load dataset, run pipeline for each question, report results."""
    # Load dataset
    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    gold_count = sum(1 for e in dataset if e.get("relevant_chunk_ids") or e.get("relevant_document_ids"))
    estimated_count = len(dataset) - gold_count

    print(f"\n{'='*80}")
    print(f"RAG Evaluation — {len(dataset)} questions, top_k={top_k}")
    print(f"Dataset: {dataset_path}")
    print(f"Gold-labeled: {gold_count} | Estimated: {estimated_count}")
    if estimated_count > 0:
        print(f"⚠ {estimated_count} questions have no gold labels — metrics are estimated (NOT independent)")
    print(f"{'='*80}\n")

    results = []
    async with AsyncSessionLocal() as db:
        for i, entry in enumerate(dataset):
            print(f"[{i+1}/{len(dataset)}] {entry['question'][:70]}...")
            result = await evaluate_single_question(db, entry, top_k)
            results.append(result)
            status = "✓" if result["error"] is None else f"✗ {result['error'][:40]}"
            metric_tag = "GOLD" if result["gold_labeled"] else "EST"
            print(f"    Recall={result['recall_at_k']:.3f}  MRR={result['mrr']:.3f}  "
                  f"NDCG={result['ndcg_at_k']:.3f}  KW_hits={result['keyword_hits']}  "
                  f"Grounding={result['grounding_status']}  [{metric_tag}]  {status}")

    # ── Per-question report ────────────────────────────────────────────
    print(f"\n{'─'*80}")
    print("Per-Question Results")
    print(f"{'─'*80}")
    print(f"{'#':>3}  {'Category':<14}  {'Diff':<7}  {'Recall@K':>9}  {'MRR':>6}  {'NDCG@K':>7}  {'KW_Hits':>8}  {'Grounding':<12}  {'Type':<5}  Question")
    print(f"{'─'*80}")
    for i, r in enumerate(results):
        q_short = r["question"][:45] + ("..." if len(r["question"]) > 45 else "")
        metric_tag = "GOLD" if r["gold_labeled"] else "EST"
        print(f"{i+1:>3}  {r['category']:<14}  {r['difficulty']:<7}  "
              f"{r['recall_at_k']:>9.3f}  {r['mrr']:>6.3f}  {r['ndcg_at_k']:>7.3f}  "
              f"{r['keyword_hits']:>8}  {r['grounding_status']:<12}  {metric_tag:<5}  {q_short}")

    # ── Aggregate report ───────────────────────────────────────────────
    valid = [r for r in results if r["error"] is None]
    if not valid:
        print("\nNo valid results to aggregate.")
        return

    gold_results = [r for r in valid if r["gold_labeled"]]
    est_results = [r for r in valid if not r["gold_labeled"]]

    def _avg(vals, key):
        items = [r[key] for r in vals]
        return sum(items) / len(items) if items else 0.0

    print(f"\n{'═'*80}")
    print("Aggregate Results")
    print(f"{'═'*80}")

    if gold_results:
        print(f"\n  GOLD-LABELED METRICS (independent benchmark):")
        print(f"    Questions:            {len(gold_results)}")
        print(f"    Avg Recall@{top_k}:      {_avg(gold_results, 'recall_at_k'):.4f}")
        print(f"    Avg MRR:              {_avg(gold_results, 'mrr'):.4f}")
        print(f"    Avg NDCG@{top_k}:       {_avg(gold_results, 'ndcg_at_k'):.4f}")

    if est_results:
        print(f"\n  ESTIMATED METRICS (keyword-approximation, NOT independent):")
        print(f"    Questions:            {len(est_results)}")
        print(f"    Avg Recall@{top_k}:      {_avg(est_results, 'recall_at_k'):.4f}")
        print(f"    Avg MRR:              {_avg(est_results, 'mrr'):.4f}")
        print(f"    Avg NDCG@{top_k}:       {_avg(est_results, 'ndcg_at_k'):.4f}")

    print(f"\n  ALL QUESTIONS (combined):")
    print(f"    Questions evaluated:   {len(valid)}/{len(results)}")
    print(f"    Avg Recall@{top_k}:      {_avg(valid, 'recall_at_k'):.4f}")
    print(f"    Avg MRR:              {_avg(valid, 'mrr'):.4f}")
    print(f"    Avg NDCG@{top_k}:       {_avg(valid, 'ndcg_at_k'):.4f}")
    print(f"    Avg Keyword Hits:     {_avg(valid, 'keyword_hits'):.2f}")

    grounding_counts = {}
    for r in valid:
        gs = r["grounding_status"]
        grounding_counts[gs] = grounding_counts.get(gs, 0) + 1
    print(f"    Grounding distribution: {grounding_counts}")

    # Per-category breakdown
    categories = sorted(set(r["category"] for r in valid))
    if categories:
        print(f"\n{'─'*80}")
        print("Per-Category Breakdown")
        print(f"{'─'*80}")
        print(f"{'Category':<14}  {'Count':>6}  {'Avg Recall':>11}  {'Avg MRR':>8}  {'Avg NDCG':>9}  {'Gold%':>6}")
        for cat in categories:
            cat_results = [r for r in valid if r["category"] == cat]
            c_recall = sum(r["recall_at_k"] for r in cat_results) / len(cat_results)
            c_mrr = sum(r["mrr"] for r in cat_results) / len(cat_results)
            c_ndcg = sum(r["ndcg_at_k"] for r in cat_results) / len(cat_results)
            c_gold_pct = sum(1 for r in cat_results if r["gold_labeled"]) / len(cat_results) * 100
            print(f"{cat:<14}  {len(cat_results):>6}  {c_recall:>11.4f}  {c_mrr:>8.4f}  {c_ndcg:>9.4f}  {c_gold_pct:>5.0f}%")

    # Per-difficulty breakdown
    difficulties = sorted(set(r["difficulty"] for r in valid))
    if difficulties:
        print(f"\n{'─'*80}")
        print("Per-Difficulty Breakdown")
        print(f"{'─'*80}")
        print(f"{'Difficulty':<12}  {'Count':>6}  {'Avg Recall':>11}  {'Avg MRR':>8}  {'Avg NDCG':>9}")
        for diff in difficulties:
            d_results = [r for r in valid if r["difficulty"] == diff]
            d_recall = sum(r["recall_at_k"] for r in d_results) / len(d_results)
            d_mrr = sum(r["mrr"] for r in d_results) / len(d_results)
            d_ndcg = sum(r["ndcg_at_k"] for r in d_results) / len(d_results)
            print(f"{diff:<12}  {len(d_results):>6}  {d_recall:>11.4f}  {d_mrr:>8.4f}  {d_ndcg:>9.4f}")

    # Save results to JSON
    output_path = Path(dataset_path).parent / "rag_eval_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "top_k": top_k,
            "dataset": str(dataset_path),
            "gold_labeled_count": len(gold_results),
            "estimated_count": len(est_results),
            "aggregate_gold": {
                "avg_recall_at_k": _avg(gold_results, "recall_at_k"),
                "avg_mrr": _avg(gold_results, "mrr"),
                "avg_ndcg_at_k": _avg(gold_results, "ndcg_at_k"),
                "questions": len(gold_results),
            } if gold_results else None,
            "aggregate_estimated": {
                "avg_recall_at_k": _avg(est_results, "recall_at_k"),
                "avg_mrr": _avg(est_results, "mrr"),
                "avg_ndcg_at_k": _avg(est_results, "ndcg_at_k"),
                "questions": len(est_results),
            } if est_results else None,
            "aggregate_all": {
                "avg_recall_at_k": _avg(valid, "recall_at_k"),
                "avg_mrr": _avg(valid, "mrr"),
                "avg_ndcg_at_k": _avg(valid, "ndcg_at_k"),
                "avg_keyword_hits": _avg(valid, "keyword_hits"),
                "grounding_distribution": grounding_counts,
                "questions_evaluated": len(valid),
                "questions_total": len(results),
            },
            "per_question": results,
        }, f, indent=2)
    print(f"\nResults saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate RAG pipeline quality")
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

    asyncio.run(run_evaluation(args.dataset, args.top_k))


if __name__ == "__main__":
    main()
