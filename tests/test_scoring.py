import pytest

from spammaild.scoring import (
    SPAM_FROM,
    SUSPICIOUS_FROM,
    Band,
    Source,
    band_for,
    combine,
    make_signal,
)


def test_signals_are_never_removed():
    signals = [
        make_signal("content_model", 3.0, "İçerik spam", Source.CONTENT),
        make_signal("auth_all_pass", -1.0, "Kimlik geçti", Source.AUTH),
        make_signal("url_foreign_domain", 1.0, "Başka alan adı", Source.URL),
    ]
    verdict = combine(signals)
    assert {signal.reason for signal in verdict.signals} == {s.reason for s in signals}


def test_signals_sorted_by_absolute_impact():
    verdict = combine(
        [
            make_signal("url_shortener", 1.0, "küçük", Source.URL),
            make_signal("auth_all_pass", -1.0, "orta", Source.AUTH),
            make_signal("attachment_infected", 3.0, "büyük", Source.ATTACHMENT),
        ]
    )
    assert [signal.reason for signal in verdict.signals] == ["büyük", "orta", "küçük"]


def test_empty_signal_list_still_has_a_reason():
    verdict = combine([])
    assert len(verdict.signals) == 1
    assert verdict.signals[0].reason


@pytest.mark.parametrize(
    ("risk", "band"),
    [
        (0, Band.CLEAN),
        (SUSPICIOUS_FROM - 1, Band.CLEAN),
        (SUSPICIOUS_FROM, Band.SUSPICIOUS),
        (SPAM_FROM - 1, Band.SUSPICIOUS),
        (SPAM_FROM, Band.SPAM),
        (100, Band.SPAM),
    ],
)
def test_band_boundaries(risk, band):
    assert band_for(risk) == band


def test_risk_is_monotonic_and_bounded():
    low = combine([make_signal("content_model", -4.0, "temiz", Source.CONTENT)])
    high = combine([make_signal("content_model", 4.0, "spam", Source.CONTENT)])
    extreme = combine([make_signal("attachment_infected", 100.0, "virüs", Source.ATTACHMENT)])
    assert 0 <= low.risk < high.risk <= extreme.risk <= 100
    assert low.band == Band.CLEAN
    assert extreme.band == Band.SPAM


def test_positive_auth_cannot_hide_infected_attachment():
    verdict = combine(
        [
            make_signal("auth_all_pass", -1.0, "Kimlik geçti", Source.AUTH),
            make_signal("content_model", -2.0, "İçerik temiz", Source.CONTENT),
            make_signal("attachment_infected", 3.0, "ClamAV zararlı buldu", Source.ATTACHMENT),
        ]
    )
    assert verdict.band != Band.CLEAN
    assert any("zararlı" in signal.reason for signal in verdict.signals)
