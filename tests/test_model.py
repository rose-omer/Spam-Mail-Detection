import json
import shutil

import pytest

from spammaild.analyzers.content import (
    ModelUnavailableError,
    SkopsLinearModel,
    analyze_content,
    detect_language,
    fold_turkish,
    sha256_file,
)
from spammaild.settings import DEFAULT_MODEL_PATH


def test_artifact_sha256_matches_metadata():
    meta = json.loads((DEFAULT_MODEL_PATH / "metadata.json").read_text(encoding="utf-8"))
    for entry in meta["files"].values():
        assert sha256_file(DEFAULT_MODEL_PATH / entry["file"]) == entry["sha256"]
    assert not list(DEFAULT_MODEL_PATH.glob("*.pkl"))


@pytest.mark.parametrize(
    ("text", "is_spam"),
    [
        ("Tebrikler! Büyük ödülü kazandınız. Hemen tıklayın ve ücretsiz hediyenizi alın.", True),
        ("Merhaba Ayşe, yarınki toplantı saat 14:00 de. Sunum dosyasını ekte gönderiyorum.", False),
        ("Congratulations! You have won a free iPhone. Click here now to claim your prize.", True),
        (
            "Hi John, attached is the agenda for Monday. Let me know if you have questions.",
            False,
        ),
        (
            "Sayın müşterimiz, hesabınız askıya alındı. Kimlik doğrulaması için hemen tıklayın.",
            True,
        ),
    ],
)
def test_fixed_examples(content_model, text, is_spam):
    assert (content_model.predict(text).spam_probability >= 0.5) is is_spam


def test_turkish_folding_avoids_lower_trap():
    assert fold_turkish("IĞDIR İSTANBUL Şişli") == "igdir istanbul sisli"


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("Merhaba, toplantı için teşekkürler", "tr"),
        ("Hello, thanks for the update", "en"),
        ("12345", "unknown"),
    ],
)
def test_detect_language(text, lang):
    assert detect_language(text) == lang


def test_tampered_artifact_is_rejected(tmp_path):
    target = tmp_path / "legacy-lr"
    shutil.copytree(DEFAULT_MODEL_PATH, target)
    with (target / "tr.skops").open("ab") as handle:
        handle.write(b"x")
    with pytest.raises(ModelUnavailableError, match="sha256"):
        SkopsLinearModel(target)


def test_missing_model_yields_error_signal():
    signals, result = analyze_content(None, "metin")
    assert result is None
    assert signals[0].status == "error"


def test_spam_reason_lists_terms(content_model):
    signals, result = analyze_content(content_model, "Hemen tıklayın, ücretsiz hediye kazandınız!")
    assert result is not None and result.spam_probability > 0.5
    assert "Öne çıkan terimler" in signals[0].reason


def test_transformer_adapter_fails_cleanly_without_artifacts(tmp_path):
    from spammaild.analyzers.content import load_content_model

    with pytest.raises(ModelUnavailableError):
        load_content_model("onnx-transformer", tmp_path)
    with pytest.raises(ModelUnavailableError):
        load_content_model("bilinmeyen", tmp_path)
