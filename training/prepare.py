"""Eğitim verisini hazırlar: kopyaları sha256 ile ayıklar, dil etiketi koyar, kaynağa göre böler.

Veri indirmez. Veri setlerini önce elle indirin (lisanslar README'de) ve CSV ya da JSONL olarak
verin. Her kaynak `ad=yol:metin_kolonu:etiket_kolonu[:synthetic]` biçimindedir. Etiket 1 = spam.

Örnek:
    python -m training.prepare \\
        --source uci_tr=data/raw/uci_tr.csv:text:label \\
        --source enron=data/raw/enron.csv:text:label \\
        --source olta=data/raw/olta.jsonl:body:is_phish:synthetic

Kural: sentetik kaynaklar yalnız eğitime girer. Doğrulama ve test gerçek maillerden oluşur.
Bölme kaynak içinde yapılır; aynı metin iki kümede bulunmaz.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

from spammaild.analyzers.content import detect_language, fold_turkish

OUT_DIR = Path("data/processed")


@dataclass(frozen=True)
class Source:
    name: str
    path: Path
    text_col: str
    label_col: str
    synthetic: bool


def parse_source(spec: str) -> Source:
    name, _, rest = spec.partition("=")
    parts = rest.split(":")
    if not name or len(parts) < 3:
        raise argparse.ArgumentTypeError(f"Geçersiz kaynak: {spec}")
    return Source(name, Path(parts[0]), parts[1], parts[2], parts[3:] == ["synthetic"])


def read_rows(source: Source) -> list[dict]:
    if source.path.suffix == ".jsonl":
        with source.path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    with source.path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def text_hash(text: str) -> str:
    normalized = " ".join(fold_turkish(text).split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=parse_source, action="append", required=True)
    parser.add_argument("--val", type=float, default=0.1)
    parser.add_argument("--test", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    seen: set[str] = set()
    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for source in args.source:
        rows = []
        for row in read_rows(source):
            text = str(row.get(source.text_col) or "").strip()
            if not text:
                continue
            digest = text_hash(text)
            if digest in seen:
                continue  # kaynaklar arası kopya (ör. UCI ve anilguven setleri)
            seen.add(digest)
            label = int(
                str(row[source.label_col]).strip().lower() in {"1", "spam", "phishing", "true"}
            )
            rows.append(
                {
                    "text": text,
                    "label": label,
                    "lang": detect_language(text),
                    "source": source.name,
                    "synthetic": source.synthetic,
                    "sha256": digest,
                }
            )
        rng.shuffle(rows)
        if source.synthetic:
            splits["train"] += rows
            continue
        n_test = int(len(rows) * args.test)
        n_val = int(len(rows) * args.val)
        splits["test"] += rows[:n_test]
        splits["val"] += rows[n_test : n_test + n_val]
        splits["train"] += rows[n_test + n_val :]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, rows in splits.items():
        with (OUT_DIR / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"{name}: {len(rows)} satır")


if __name__ == "__main__":
    main()
