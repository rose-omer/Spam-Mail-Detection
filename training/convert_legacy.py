"""Eski pickle modellerini skops biçimine bir kez çevirir.

Bu betik yeniden eğitim yapmaz. Yalnız eski `model/*.pkl` dosyalarını açar,
sha256 değerlerini bilinen değerlerle karşılaştırır ve her dil için bir
`Pipeline(vectorizer, model)` nesnesini skops ile kaydeder.

Eski pkl dosyaları repodan kaldırıldı. Betiği koşmak için onları git geçmişinden
geri al:

    git show 2407db2:model/model_tr.pkl > model/model_tr.pkl   # diğer üç dosya için de

Sonra:

    python -m training.convert_legacy
"""

from __future__ import annotations

import hashlib
import json
import pickle
import zipfile
from pathlib import Path

import sklearn
import skops
import skops.io as sio
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
LEGACY_DIR = ROOT / "model"
OUT_DIR = ROOT / "models" / "legacy-lr"

# Repodaki son commit'te (2407db2) bulunan dosyaların sha256 değerleri.
KNOWN_SHA256 = {
    "model_tr.pkl": "d82b7f28e916eb3b6386dd95fd075eb07c83512b74294ba80c8e26884375e456",
    "vectorizer_tr.pkl": "b7f82d99ac26118c5fd62618e9c6fcacaa834714ab0b9cca0cecfacfe91ea3e2",
    "model_en.pkl": "52212b0105c7f9224814bfc978585d824148c016ad403af08bee755ff4195c1c",
    "vectorizer_en.pkl": "2fbad2347bb75bf8eee9819c303fdb563b8d25c6e7dd2705b800cba8ec879f34",
}


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_verified_pickle(name: str) -> object:
    path = LEGACY_DIR / name
    digest = sha256_of(path)
    if digest != KNOWN_SHA256[name]:
        raise SystemExit(f"{name}: sha256 uyuşmuyor ({digest}). Dosyayı açmıyorum.")
    with path.open("rb") as handle:
        return pickle.load(handle)  # sha256 yukarıda doğrulandı


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict[str, str]] = {}
    for lang in ("tr", "en"):
        vectorizer = load_verified_pickle(f"vectorizer_{lang}.pkl")
        # `stop_words_` yalnız bilgi amaçlı; sklearn belgesi silinebilir diyor. Dosyayı şişiriyor.
        if hasattr(vectorizer, "stop_words_"):
            delattr(vectorizer, "stop_words_")
        pipeline = Pipeline(
            [("vectorizer", vectorizer), ("model", load_verified_pickle(f"model_{lang}.pkl"))]
        )
        out = OUT_DIR / f"{lang}.skops"
        sio.dump(pipeline, out, compression=zipfile.ZIP_DEFLATED, compresslevel=9)
        files[lang] = {"file": out.name, "sha256": sha256_of(out)}
        print(f"{lang}: {out} yazıldı")

    metadata = {
        "name": "legacy-lr",
        "version": "1.0.0-legacy",
        "description": "Staj sürümündeki LogisticRegression modelleri (TR: TF-IDF, EN: Count).",
        "trained_with": {"scikit-learn": "1.2.2"},
        "converted_with": {"scikit-learn": sklearn.__version__, "skops": skops.__version__},
        "preprocessing": "Türkçe harfler ASCII'ye katlanır (ç→c, ğ→g, ı→i, ö→o, ş→s, ü→u).",
        "training_data": "bilinmiyor (repoda eğitim kodu ve veri yok)",
        "metrics": None,
        "files": files,
    }
    (OUT_DIR / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
