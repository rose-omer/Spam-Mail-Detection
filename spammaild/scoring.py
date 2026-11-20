"""Sinyalleri log-odds üzerinden tek risk skoruna çevirir.

Kural: hiçbir sinyal başka bir sinyali silmez. Her sinyal nedenini rapora yazar.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum


class Source(StrEnum):
    CONTENT = "content"
    AUTH = "auth"
    URL = "url"
    ATTACHMENT = "attachment"


class Band(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    SPAM = "spam"


@dataclass(frozen=True, slots=True)
class Signal:
    """Bir analizin tek bulgusu.

    `score` log-odds birimindedir: pozitif değer riski artırır, negatif değer azaltır.
    Etki = `score * weight`. `status` bulgunun güvenilirliğini taşır (ör. `unknown`).
    """

    name: str
    score: float
    weight: float
    reason: str
    source: Source
    status: str = "ok"

    @property
    def impact(self) -> float:
        return self.score * self.weight


# Ağırlık tablosu. Değerler elle ayarlandı; doğrulama kümesi gelince yeniden ayarlanmalı.
WEIGHTS: dict[str, float] = {
    "content_model": 1.0,
    "auth_spf_fail": 1.0,
    "auth_dkim_fail": 1.0,
    "auth_dmarc_fail": 1.5,
    "auth_all_pass": 1.0,
    "auth_untrusted": 0.3,
    "auth_dkim_misaligned": 0.6,
    "display_name_spoof": 1.5,
    "url_text_mismatch": 1.2,
    "url_ip_literal": 1.2,
    "url_punycode": 1.0,
    "url_shortener": 0.5,
    "url_foreign_domain": 0.4,
    "url_reputation_bad": 2.5,
    "attachment_infected": 4.0,
    "attachment_double_extension": 1.5,
    "attachment_executable": 1.5,
    "attachment_macro": 1.2,
    "attachment_encrypted_archive": 1.0,
    "attachment_too_large": 0.5,
    "attachment_scan_unknown": 0.2,
    "no_signal": 1.0,
}

# Model sinyali yokken başlangıç log-odds'u. Hafif "temiz" yönlü.
BASE_LOGIT = -1.0
SUSPICIOUS_FROM = 35
SPAM_FROM = 65


def weight_for(name: str) -> float:
    return WEIGHTS.get(name, 1.0)


def make_signal(name: str, score: float, reason: str, source: Source, status: str = "ok") -> Signal:
    return Signal(
        name=name, score=score, weight=weight_for(name), reason=reason, source=source, status=status
    )


def band_for(risk: int) -> Band:
    if risk >= SPAM_FROM:
        return Band.SPAM
    if risk >= SUSPICIOUS_FROM:
        return Band.SUSPICIOUS
    return Band.CLEAN


@dataclass(frozen=True, slots=True)
class Verdict:
    risk: int
    band: Band
    signals: list[Signal]


def combine(signals: list[Signal], base_logit: float = BASE_LOGIT) -> Verdict:
    """Sinyalleri toplar. Dönen listede her sinyal korunur; etkiye göre sıralanır."""
    items = list(signals)
    if not items:
        items.append(
            make_signal("no_signal", 0.0, "Belirgin bir risk sinyali bulunmadı.", Source.CONTENT)
        )
    logit = base_logit + sum(signal.impact for signal in items)
    logit = max(min(logit, 30.0), -30.0)
    risk = round(100 / (1 + math.exp(-logit)))
    ordered = sorted(items, key=lambda signal: abs(signal.impact), reverse=True)
    return Verdict(risk=risk, band=band_for(risk), signals=ordered)
