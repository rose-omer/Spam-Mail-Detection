"""Bir içerik modelini test kümesinde değerlendirir ve `reports/metrics.json` dosyasına yazar.

Ölçütler: PR-AUC, F1 (eşik 0.5), recall %95'te yanlış pozitif oranı. Hepsi genel ve dil bazında.

    python -m training.evaluate --backend legacy-lr --model-path models/legacy-lr
    python -m training.evaluate --backend baseline-char --model-path models/baseline-char
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, f1_score, roc_curve

from spammaild.analyzers.content import load_content_model

DATA = Path("data/processed/test.jsonl")
REPORT = Path("reports/metrics.json")


def fpr_at_recall(y_true: np.ndarray, scores: np.ndarray, recall: float = 0.95) -> float | None:
    if y_true.min() == y_true.max():
        return None
    fpr, tpr, _ = roc_curve(y_true, scores)
    index = int(np.searchsorted(tpr, recall, side="left"))
    return float(fpr[min(index, len(fpr) - 1)])


def metrics(y_true: np.ndarray, scores: np.ndarray) -> dict:
    if len(y_true) == 0:
        return {"n": 0}
    has_both = y_true.min() != y_true.max()
    return {
        "n": len(y_true),
        "spam_ratio": round(float(y_true.mean()), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4) if has_both else None,
        "f1": round(float(f1_score(y_true, scores >= 0.5)), 4),
        "fpr_at_recall_95": fpr_at_recall(y_true, scores),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Model değerlendirmesi")
    parser.add_argument("--backend", default="legacy-lr")
    parser.add_argument("--model-path", type=Path, default=Path("models/legacy-lr"))
    args = parser.parse_args()

    model = load_content_model(args.backend, args.model_path)
    with DATA.open(encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    scores = np.array([model.predict(row["text"]).spam_probability for row in rows])
    labels = np.array([int(row["label"]) for row in rows])
    langs = np.array([row["lang"] for row in rows])

    entry = {
        "model": model.name,
        "version": model.version,
        "evaluated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "overall": metrics(labels, scores),
        "by_language": {
            lang: metrics(labels[langs == lang], scores[langs == lang])
            for lang in sorted(set(langs))
        },
    }
    report = json.loads(REPORT.read_text(encoding="utf-8")) if REPORT.exists() else {}
    report[model.name] = entry
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(entry, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
