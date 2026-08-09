"""RAGAS evaluation script for correlation_reasoner_node output.

Metrics: faithfulness, context precision, context recall.
"""
import os
import sys
import asyncio
import json
import csv
from typing import List, Dict

from datasets import Dataset
from ragas import evaluate
from ragas.metrics import Faithfulness, LLMContextPrecisionWithReference, LLMContextRecall
from langchain_groq import ChatGroq
from voyageai import Client

# Judge LLM via Groq
JUDGE_MODEL = os.environ.get("JUDGE_LLM_MODEL", "llama-3.3-70b-versatile")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")


def load_eval_data(csv_path: str) -> List[Dict]:
    """Load eval dataset: question=alert summary, answer=reasoning, contexts=retrieved docs."""
    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            contexts = []
            if row.get("retrieved_incidents"):
                contexts.extend(row["retrieved_incidents"].split("||"))
            if row.get("retrieved_cves"):
                contexts.extend(row["retrieved_cves"].split("||"))
            if row.get("retrieved_mitre"):
                contexts.extend(row["retrieved_mitre"].split("||"))
            rows.append({
                "question": row["alert_summary"],
                "answer": row["reasoning"],
                "contexts": contexts,
                "reference": row.get("ground_truth_reasoning", row["reasoning"]),
            })
    return rows


def run_ragas_eval(data: List[Dict]):
    judge_llm = ChatGroq(model=JUDGE_MODEL, groq_api_key=GROQ_API_KEY, temperature=0)

    # Use Voyage AI for embeddings (no OpenAI fallback)
    voyage_client = Client(api_key=os.environ.get("VOYAGE_API_KEY"))
    from langchain_core.embeddings import Embeddings

    class VoyageEmbeddings(Embeddings):
        def embed_documents(self, texts: List[str]) -> List[List[float]]:
            return voyage_client.embed(texts, model="voyage-3").embeddings
        def embed_query(self, text: str) -> List[float]:
            return voyage_client.embed([text], model="voyage-3").embeddings[0]

    judge_embeddings = VoyageEmbeddings()

    dataset = Dataset.from_dict({
        "question": [d["question"] for d in data],
        "answer": [d["answer"] for d in data],
        "contexts": [d["contexts"] for d in data],
        "reference": [d["reference"] for d in data],
    })

    result = evaluate(
        dataset=dataset,
        metrics=[
            Faithfulness(llm=judge_llm),
            LLMContextPrecisionWithReference(llm=judge_llm),
            LLMContextRecall(llm=judge_llm),
        ],
        llm=judge_llm,
        embeddings=judge_embeddings,
    )

    df = result.to_pandas()
    print("\n--- RAGAS Evaluation Results ---")
    print(df[["question", "faithfulness", "context_precision", "context_recall"]])
    print("\n--- Aggregate ---")
    print(df[["faithfulness", "context_precision", "context_recall"]].mean())

    df.to_csv("eval/ragas_results.csv", index=False)
    return df


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "eval/eval_dataset.csv"
    if not os.path.exists(csv_path):
        print(f"Eval dataset not found at {csv_path}")
        print("Expected columns: alert_summary, reasoning, retrieved_incidents, retrieved_cves, retrieved_mitre, ground_truth_reasoning")
        sys.exit(1)

    data = load_eval_data(csv_path)
    run_ragas_eval(data)


if __name__ == "__main__":
    main()
