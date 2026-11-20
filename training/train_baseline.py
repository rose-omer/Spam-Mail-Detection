"""Taban modeli eğitir: karakter n-gram TF-IDF + LogisticRegression. skops ile kaydeder.

Girdi: `data/processed/{train,val}.jsonl` (`training.prepare` çıktısı).
Çıktı: `models/baseline-char/{all.skops, metadata.json}`.

    python -m training.train_baseline
    MODEL_BACKEND=baseline-char MODEL_PATH=models/baseline-char uvicorn ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

import sklearn
import skops
import skops.io as sio
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline

from spammaild.analyzers.content import fold_turkish

DATA_DIR = Path("data/processed")
OUT_DIR = Path("models/baseline-char")


def load(name: str) -> tuple[list[str], list[int]]:
    with (DATA_DIR / f"{name}.jsonl").open(encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    return [row["text"] for row in rows], [int(row["label"]) for row in rows]


def build_pipeline(c: float) -> Pipeline:
    # Türkçe küçük harf tuzağı: str.lower() yerine fold_turkish (İ/I → i, ı → i).
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        preprocessor=fold_turkish,
        lowercase=False,
        min_df=2,
        max_features=200_000,
        sublinear_tf=True,
    )
    model = LogisticRegression(C=c, max_iter=2000, class_weight="balanced")
    return Pipeline([("vectorizer", vectorizer), ("model", model)])


def main() -> None:
    parser = argparse.ArgumentParser(description="Taban model eğitimi")
    parser.add_argument("--c", type=float, nargs="+", default=[0.5, 1.0, 4.0])
    args = parser.parse_args()

    x_train, y_train = load("train")
    x_val, y_val = load("val")
    best: tuple[float, float, Pipeline] | None = None
    for c in args.c:
        pipeline = build_pipeline(c).fit(x_train, y_train)
        score = average_precision_score(y_val, pipeline.predict_proba(x_val)[:, 1])
        print(f"C={c}: val PR-AUC={score:.4f}")
        if best is None or score > best[0]:
            best = (score, c, pipeline)
    assert best is not None
    score, c, pipeline = best

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "all.skops"
    sio.dump(pipeline, out, compression=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    metadata = {
        "name": "baseline-char",
        "version": "1.0.0",
        "description": "char_wb (3,5) TF-IDF + LogisticRegression, TR ve EN tek model.",
        "trained_with": {"scikit-learn": sklearn.__version__, "skops": skops.__version__},
        "hyperparameters": {"C": c},
        "validation": {"pr_auc": round(score, 4)},
        "training_data": sorted(
            {
                json.loads(line)["source"]
                for line in (DATA_DIR / "train.jsonl").open(encoding="utf-8")
            }
        ),
        "files": {"all": {"file": out.name, "sha256": digest}},
    }
    (OUT_DIR / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Kaydedildi: {out} (sha256 {digest[:12]}…)")


if __name__ == "__main__":
    main()
