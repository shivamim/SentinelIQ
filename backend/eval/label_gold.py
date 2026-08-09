"""Gold-labeling tool for the RAG evaluation dataset.

This script queries the database for documents/chunks matching each question's
expected keywords and document types, and populates the relevant_document_ids
and relevant_chunk_ids fields in rag_dataset.json.

Usage:
    # Dry run — show what would be labeled
    python -m eval.label_gold --dry-run

    # Apply labels to the dataset
    python -m eval.label_gold

    # Label a specific question by index
    python -m eval.label_gold --index 0 --chunk-ids "chunk-id-1,chunk-id-2"

This provides a DETERMINISTIC mechanism for generating gold labels from the
actual database content, making the evaluation a valid independent benchmark.
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Set

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.database import AsyncSessionLocal
from sqlalchemy import text


async def find_relevant_chunks(
    db,
    expected_keywords: List[str],
    expected_document_types: List[str],
    top_k: int = 10,
) -> Dict[str, Any]:
    """Find chunks matching expected keywords and document types.

    Returns dict with relevant_document_ids and relevant_chunk_ids.
    """
    if not expected_keywords or not expected_document_types:
        return {"relevant_document_ids": [], "relevant_chunk_ids": []}

    # Build tsquery from keywords
    ts_query = " & ".join(expected_keywords)

    # Build document type filter
    dt_placeholders = ", ".join(f":dt_{i}" for i in range(len(expected_document_types)))
    params = {
        "query": ts_query,
        "limit": top_k,
    }
    for i, dt in enumerate(expected_document_types):
        params[f"dt_{i}"] = dt

    sql = text(f"""
        SELECT dc.id as chunk_id, dc.document_id, dc.chunk_text,
               d.title, d.document_type,
               ts_rank_cd(dc.search_vector, plainto_tsquery(:query)) as score
        FROM document_chunks dc
        JOIN documents d ON d.id = dc.document_id
        WHERE dc.search_vector @@ plainto_tsquery(:query)
          AND d.document_type IN ({dt_placeholders})
        ORDER BY score DESC
        LIMIT :limit
    """)

    try:
        result = await db.execute(sql, params)
        rows = result.mappings().all()

        chunk_ids = [str(r["chunk_id"]) for r in rows]
        doc_ids = list(set(str(r["document_id"]) for r in rows))

        return {
            "relevant_document_ids": doc_ids,
            "relevant_chunk_ids": chunk_ids,
        }
    except Exception as e:
        print(f"  ⚠ Query failed: {e}")
        return {"relevant_document_ids": [], "relevant_chunk_ids": []}


async def auto_label(dry_run: bool = False) -> None:
    """Auto-label the dataset by querying the database for matching chunks."""
    dataset_path = Path(__file__).resolve().parent / "rag_dataset.json"
    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    print(f"Auto-labeling {len(dataset)} questions from database...")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}\n")

    changes = 0
    async with AsyncSessionLocal() as db:
        for i, entry in enumerate(dataset):
            question = entry["question"]
            expected_kws = entry.get("expected_keywords", [])
            expected_types = entry.get("expected_document_types", [])

            print(f"[{i+1}/{len(dataset)}] {question[:70]}...")

            result = await find_relevant_chunks(db, expected_kws, expected_types)

            chunk_count = len(result["relevant_chunk_ids"])
            doc_count = len(result["relevant_document_ids"])

            if chunk_count > 0:
                print(f"  ✓ Found {chunk_count} relevant chunks in {doc_count} documents")
                if not dry_run:
                    entry["relevant_chunk_ids"] = result["relevant_chunk_ids"]
                    entry["relevant_document_ids"] = result["relevant_document_ids"]
                    entry["gold_labeled"] = True
                    changes += 1
            else:
                print(f"  ✗ No matching chunks found — needs manual labeling")

    if not dry_run and changes > 0:
        with open(dataset_path, "w") as f:
            json.dump(dataset, f, indent=2)
        print(f"\n✓ Applied labels to {changes} questions. Dataset saved to {dataset_path}")
    elif dry_run:
        print(f"\n(Dry run — no changes written)")
    else:
        print(f"\nNo new labels to apply.")


async def manual_label(index: int, chunk_ids: str = None, doc_ids: str = None) -> None:
    """Manually set gold labels for a specific question."""
    dataset_path = Path(__file__).resolve().parent / "rag_dataset.json"
    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    if index < 0 or index >= len(dataset):
        print(f"Error: index {index} out of range (0-{len(dataset)-1})")
        return

    entry = dataset[index]
    print(f"Question: {entry['question']}")

    if chunk_ids:
        entry["relevant_chunk_ids"] = [cid.strip() for cid in chunk_ids.split(",") if cid.strip()]
        entry["gold_labeled"] = True
        print(f"  Set {len(entry['relevant_chunk_ids'])} relevant chunk IDs")

    if doc_ids:
        entry["relevant_document_ids"] = [did.strip() for did in doc_ids.split(",") if did.strip()]
        entry["gold_labeled"] = True
        print(f"  Set {len(entry['relevant_document_ids'])} relevant document IDs")

    with open(dataset_path, "w") as f:
        json.dump(dataset, f, indent=2)
    print(f"\n✓ Labels saved for question {index}")


def main():
    parser = argparse.ArgumentParser(description="Gold-label RAG evaluation dataset")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be labeled without writing changes",
    )
    parser.add_argument(
        "--index", type=int, default=None,
        help="Index of question to manually label",
    )
    parser.add_argument(
        "--chunk-ids", type=str, default=None,
        help="Comma-separated chunk IDs for manual labeling",
    )
    parser.add_argument(
        "--doc-ids", type=str, default=None,
        help="Comma-separated document IDs for manual labeling",
    )
    args = parser.parse_args()

    if args.index is not None:
        asyncio.run(manual_label(args.index, args.chunk_ids, args.doc_ids))
    else:
        asyncio.run(auto_label(args.dry_run))


if __name__ == "__main__":
    main()
