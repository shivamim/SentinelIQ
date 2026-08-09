"""Custom verdict accuracy evaluation against labeled CSV.

Expected CSV columns: alert_id, expected_verdict, expected_incident_id
Reports: precision/recall/F1 for known_pattern vs novel, false-negative rate separately.
"""
import os
import sys
import csv
from typing import List, Dict
from collections import defaultdict


def load_labels(csv_path: str) -> List[Dict]:
    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "alert_id": row["alert_id"],
                "expected_verdict": row["expected_verdict"].strip().lower(),
                "expected_incident_id": row.get("expected_incident_id", "").strip(),
                "predicted_verdict": row.get("predicted_verdict", "").strip().lower(),
            })
    return rows


def compute_metrics(rows: List[Dict]):
    tp = fp = tn = fn = 0
    false_negatives = []

    for r in rows:
        expected = r["expected_verdict"]
        predicted = r["predicted_verdict"]

        if expected == "known_pattern":
            if predicted == "known_pattern":
                tp += 1
            else:
                fn += 1
                false_negatives.append(r)
        elif expected == "novel":
            if predicted == "novel":
                tn += 1
            else:
                fp += 1
        else:
            if predicted != expected:
                fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fn_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0

    total = len(rows)
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print("\n=== Verdict Accuracy Evaluation ===")
    print(f"Total samples: {total}")
    print(f"TP (known_pattern correct): {tp}")
    print(f"FP (novel misclassified as known): {fp}")
    print(f"TN (novel correct): {tn}")
    print(f"FN (known_pattern missed): {fn}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision (known_pattern): {precision:.4f}")
    print(f"Recall (known_pattern): {recall:.4f}")
    print(f"F1 (known_pattern): {f1:.4f}")
    print(f"False Negative Rate (missing known patterns): {fn_rate:.4f}")
    print("\nNote: False negatives are the costliest error — missing a known pattern means missing a repeat incident.")

    if false_negatives:
        print(f"\nFalse Negative Details ({len(false_negatives)} cases):")
        for fn_item in false_negatives[:10]:
            print(f"  - alert_id={fn_item['alert_id']}, expected={fn_item['expected_verdict']}, predicted={fn_item['predicted_verdict']}")

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_negative_rate": fn_rate,
    }


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "eval/labeled_verdicts.csv"
    if not os.path.exists(csv_path):
        print(f"Labeled dataset not found at {csv_path}")
        print("Expected columns: alert_id, expected_verdict, expected_incident_id, predicted_verdict")
        sys.exit(1)

    rows = load_labels(csv_path)
    compute_metrics(rows)


if __name__ == "__main__":
    main()
