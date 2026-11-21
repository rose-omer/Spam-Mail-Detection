"""İçerik modeli: taban (skops) ve transformer (ONNX) için ortak arayüz."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import numpy as np

from spammaild.scoring import Signal, Source, make_signal

logger = logging.getLogger(__name__)

# skops dosyalarında beklenen ve güvenilen ek tipler (get_untrusted_types çıktısı).
TRUSTED_SKOPS_TYPES = [
    "scipy.sparse._csr.csr_matrix",
    "spammaild.analyzers.content.fold_turkish",
]

_TR_FOLD = str.maketrans(
    {
        "ç": "c",
        "Ç": "c",
        "ğ": "g",
        "Ğ": "g",
        "ı": "i",
        "I": "i",
        "İ": "i",
        "ö": "o",
        "Ö": "o",
        "ş": "s",
        "Ş": "s",
        "ü": "u",
        "Ü": "u",
        "â": "a",
        "î": "i",
        "û": "u",
    }
)
_TR_CHARS = set("çğıöşüÇĞİÖŞÜ")
_WORD_RE = re.compile(r"\w+", re.UNICODE)
_TR_WORDS = frozenset(
    "ve bir bu için ile da de çok daha olarak gibi ama sizin hemen ücretsiz hesabınız "
    "lütfen tıklayın kazandınız merhaba sayın teşekkürler".split()
)
_EN_WORDS = frozenset(
    "the and you your for with this that are have from please click free account "
    "now our will hello dear thanks".split()
)


class ModelUnavailableError(RuntimeError):
    """Model dosyası yok, bozuk ya da bağımlılığı kurulu değil."""


def fold_turkish(text: str) -> str:
    """Türkçe harfleri ASCII'ye katlar ve küçültür.

    `str.lower()` Türkçede yanlış sonuç verir ("I" → "i", "İ" → "i̇"). Bu yüzden
    önce katlama yapılır, sonra küçültülür. Eski TR modeli ASCII sözlükle eğitildi.
    """
    return text.translate(_TR_FOLD).lower()


def detect_language(text: str) -> str:
    """Basit ve deterministik dil tahmini: "tr", "en" ya da "unknown"."""
    words = [word.lower() for word in _WORD_RE.findall(text)]
    if not words:
        return "unknown"
    tr_score = sum(word in _TR_WORDS for word in words) + 2 * sum(ch in _TR_CHARS for ch in text)
    en_score = sum(word in _EN_WORDS for word in words)
    if tr_score == en_score == 0:
        return "unknown"
    return "tr" if tr_score >= en_score else "en"


@dataclass(frozen=True, slots=True)
class ContentResult:
    spam_probability: float
    language: str
    top_terms: list[tuple[str, float]] = field(default_factory=list)


class ContentModel(Protocol):
    name: str
    version: str

    def predict(self, text: str) -> ContentResult: ...


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_metadata(model_dir: Path) -> dict:
    meta_path = model_dir / "metadata.json"
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModelUnavailableError(f"metadata.json bulunamadı: {meta_path}") from exc
    except json.JSONDecodeError as exc:
        raise ModelUnavailableError(f"metadata.json okunamadı: {meta_path}") from exc


def verify_file(model_dir: Path, entry: dict) -> Path:
    path = model_dir / entry["file"]
    if not path.is_file():
        raise ModelUnavailableError(f"Model dosyası yok: {path}")
    digest = sha256_file(path)
    if digest != entry["sha256"]:
        raise ModelUnavailableError(f"sha256 uyuşmuyor: {path.name}")
    return path


class SkopsLinearModel:
    """skops ile saklanan doğrusal modeller; sha256 denetimiyle yüklenir.

    İki düzen desteklenir:
    - `legacy-lr`: dil başına bir Pipeline (`tr`, `en`); TR metni önce ASCII'ye katlanır.
    - `baseline-char`: tek çok dilli Pipeline (`all`); ön işleme Pipeline içindedir.
    """

    def __init__(self, model_dir: Path) -> None:
        import skops.io as sio

        meta = read_metadata(model_dir)
        self.name = str(meta.get("name", "legacy-lr"))
        self.version = str(meta.get("version", "0"))
        self._pipelines = {}
        self._feature_names: dict[str, np.ndarray] = {}
        for lang, entry in meta["files"].items():
            path = verify_file(model_dir, entry)
            untrusted = set(sio.get_untrusted_types(file=path)) - set(TRUSTED_SKOPS_TYPES)
            if untrusted:
                raise ModelUnavailableError(f"Beklenmeyen tipler: {sorted(untrusted)}")
            pipeline = sio.load(path, trusted=TRUSTED_SKOPS_TYPES)
            self._pipelines[lang] = pipeline
            vectorizer = pipeline.named_steps["vectorizer"]
            self._feature_names[lang] = vectorizer.get_feature_names_out()

    def predict(self, text: str) -> ContentResult:
        language = detect_language(text)
        if "all" in self._pipelines:
            model_lang, prepared = "all", text
        else:
            model_lang = language if language in self._pipelines else "en"
            prepared = fold_turkish(text) if model_lang == "tr" else text
        pipeline = self._pipelines[model_lang]
        vectorizer = pipeline.named_steps["vectorizer"]
        model = pipeline.named_steps["model"]
        features = vectorizer.transform([prepared])  # seyrek matris; yoğunlaştırılmaz
        probability = float(model.predict_proba(features)[0][1])
        return ContentResult(
            spam_probability=probability,
            language=language,
            top_terms=self._top_terms(model_lang, features, model.coef_[0]),
        )

    def _top_terms(self, lang: str, features, coefs: np.ndarray, limit: int = 5):
        row = features.tocsr()
        contributions = [
            (str(self._feature_names[lang][index]), float(coefs[index] * value))
            for index, value in zip(row.indices, row.data, strict=True)
        ]
        positive = [item for item in contributions if item[1] > 0]
        return sorted(positive, key=lambda item: item[1], reverse=True)[:limit]


class OnnxTransformerModel:
    """İnce ayarlı transformer (ör. mmBERT) için ONNX adaptörü.

    Klasörde `model.onnx`, `tokenizer.json` ve `metadata.json` bekler. Bağımlılık:
    `pip install .[transformer]`. Model `training/train_transformer.py` ile üretilir.
    """

    def __init__(self, model_dir: Path, max_length: int = 512) -> None:
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ModelUnavailableError("onnxruntime ve tokenizers kurulu değil.") from exc
        meta = read_metadata(model_dir)
        self.name = str(meta.get("name", "transformer"))
        self.version = str(meta.get("version", "0"))
        onnx_path = verify_file(model_dir, meta["files"]["onnx"])
        self._tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=max_length)
        self._session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        self._input_names = {item.name for item in self._session.get_inputs()}

    def predict(self, text: str) -> ContentResult:
        encoding = self._tokenizer.encode(text)
        feeds = {
            "input_ids": np.array([encoding.ids], dtype=np.int64),
            "attention_mask": np.array([encoding.attention_mask], dtype=np.int64),
        }
        logits = self._session.run(None, {k: v for k, v in feeds.items() if k in self._input_names})
        scores = np.asarray(logits[0][0], dtype=np.float64)
        exp = np.exp(scores - scores.max())
        probability = float(exp[1] / exp.sum())
        return ContentResult(spam_probability=probability, language=detect_language(text))


def load_content_model(backend: str, model_dir: Path) -> ContentModel:
    if backend in {"legacy-lr", "baseline-char"}:
        return SkopsLinearModel(model_dir)
    if backend == "onnx-transformer":
        return OnnxTransformerModel(model_dir)
    raise ModelUnavailableError(f"Bilinmeyen model türü: {backend}")


def _logit(probability: float) -> float:
    clipped = min(max(probability, 1e-4), 1 - 1e-4)
    return math.log(clipped / (1 - clipped))


def analyze_content(
    model: ContentModel | None, text: str, subject: str = ""
) -> tuple[list[Signal], ContentResult | None]:
    if model is None:
        return [
            make_signal(
                "content_model",
                0.0,
                "İçerik modeli yüklenemedi; içerik puanlanmadı.",
                Source.CONTENT,
                status="error",
            )
        ], None
    body = f"{subject}\n{text}".strip()
    if not body:
        return [
            make_signal(
                "content_model",
                0.0,
                "Mail gövdesi boş; içerik puanlanmadı.",
                Source.CONTENT,
                status="unknown",
            )
        ], None
    result = model.predict(body)
    percent = round(result.spam_probability * 100)
    if result.top_terms and result.spam_probability >= 0.5:
        terms = ", ".join(term for term, _ in result.top_terms)
        reason = f"İçerik modeli spam olasılığını %{percent} buldu. Öne çıkan terimler: {terms}."
    else:
        reason = f"İçerik modeli spam olasılığını %{percent} buldu."
    score = max(min(_logit(result.spam_probability), 4.0), -4.0)
    return [make_signal("content_model", score, reason, Source.CONTENT)], result
