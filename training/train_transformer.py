"""Transformer ince ayarı ve ONNX'e aktarım (mmBERT ya da TabiBERT).

Bu betik ağır bir iştir. Ek bağımlılık ister ve bu repoda henüz koşturulmadı:
    pip install "torch>=2.5" "transformers>=4.46" "datasets>=3.0" onnx

Bellek kapısı: başlamadan önce boş bellek en az 8 GB olmalı. Koşarken 5 GB altına inerse durdurun.

    TRANSFORMER_MODEL=jhu-clsp/mmBERT-base python -m training.train_transformer --epochs 2
    TRANSFORMER_MODEL=boun-tabilab/TabiBERT python -m training.train_transformer

Çıktı: `models/<ad>/{model.onnx, tokenizer.json, metadata.json}`. Servis tarafında:
    MODEL_BACKEND=onnx-transformer MODEL_PATH=models/<ad> uvicorn ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

DATA_DIR = Path("data/processed")
DEFAULT_MODEL = os.environ.get("TRANSFORMER_MODEL", "jhu-clsp/mmBERT-base")


def load_split(name: str) -> list[dict]:
    with (DATA_DIR / f"{name}.jsonl").open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def main() -> None:
    parser = argparse.ArgumentParser(description="Transformer ince ayarı")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--max-length", type=int, default=512)
    args = parser.parse_args()

    import numpy as np
    import torch
    from datasets import Dataset
    from sklearn.metrics import average_precision_score
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    out_dir = Path("models") / args.model.split("/")[-1].lower()
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)

    def encode(rows: list[dict]) -> Dataset:
        dataset = Dataset.from_list([{"text": r["text"], "label": int(r["label"])} for r in rows])
        return dataset.map(
            lambda batch: tokenizer(batch["text"], truncation=True, max_length=args.max_length),
            batched=True,
        )

    train, val = encode(load_split("train")), encode(load_split("val"))

    def compute_metrics(prediction):
        logits, labels = prediction
        probs = torch.softmax(torch.tensor(logits), dim=-1)[:, 1].numpy()
        return {"pr_auc": float(average_precision_score(labels, probs))}

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(out_dir / "checkpoints"),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch_size,
            learning_rate=args.lr,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="pr_auc",
            report_to=[],
        ),
        train_dataset=train,
        eval_dataset=val,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
    )
    trainer.train()
    val_metrics = trainer.evaluate()

    out_dir.mkdir(parents=True, exist_ok=True)
    model = trainer.model.eval().to("cpu")
    sample = tokenizer(["örnek"], return_tensors="pt")
    onnx_path = out_dir / "model.onnx"
    torch.onnx.export(
        model,
        (sample["input_ids"], sample["attention_mask"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
        },
        opset_version=17,
    )
    tokenizer.backend_tokenizer.save(str(out_dir / "tokenizer.json"))
    metadata = {
        "name": out_dir.name,
        "version": "1.0.0",
        "base_model": args.model,
        "max_length": args.max_length,
        "validation": {k: float(np.round(v, 4)) for k, v in val_metrics.items() if "pr_auc" in k},
        "files": {
            "onnx": {
                "file": onnx_path.name,
                "sha256": hashlib.sha256(onnx_path.read_bytes()).hexdigest(),
            }
        },
    }
    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"ONNX modeli yazıldı: {onnx_path}")


if __name__ == "__main__":
    main()
