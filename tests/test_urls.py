import asyncio

import httpx
import pytest

from spammaild.analyzers.urls import analyze_urls, inspect_link
from spammaild.clients.http import ScanStatus
from spammaild.clients.reputation import OpenPhishFeed, UrlhausClient
from spammaild.domains import registered_domain, same_organization
from spammaild.parsing import Link


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("paypal.com.evil.io", "evil.io"),
        ("www.paypal.com", "paypal.com"),
        ("mail.garanti.com.tr", "garanti.com.tr"),
        ("192.0.2.10", ""),
        ("", ""),
    ],
)
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_substring_match_does_not_bypass():
    # Eski kod "paypal.com" in "paypal.com.evil.io" ile bunu uyumlu sayıyordu.
    assert not same_organization("paypal.com.evil.io", "paypal.com")
    assert not same_organization("paypal.com", "notpaypal.com")
    assert same_organization("www.paypal.com", "paypal.com")


def test_paypal_evil_link_is_mismatched(parsed_fixture):
    signals, findings = asyncio.run(analyze_urls(parsed_fixture("paypal_evil_link.eml"), []))
    assert findings[0].domain == "evil.io"
    assert "foreign_domain" in findings[0].flags
    assert "url_foreign_domain" in {signal.name for signal in signals}


def test_text_href_mismatch(parsed_fixture):
    signals, findings = asyncio.run(analyze_urls(parsed_fixture("href_mismatch.eml"), []))
    assert "text_mismatch" in findings[0].flags
    assert "url_text_mismatch" in {signal.name for signal in signals}


def test_punycode_ip_and_shortener(parsed_fixture):
    signals, findings = asyncio.run(analyze_urls(parsed_fixture("punycode.eml"), []))
    flags = {flag for finding in findings for flag in finding.flags}
    assert {"punycode", "ip_literal", "shortener"} <= flags
    names = {signal.name for signal in signals}
    assert {"url_punycode", "url_ip_literal", "url_shortener"} <= names


def test_same_domain_link_has_no_flags():
    finding = inspect_link(Link(href="https://www.ornek.com.tr/a", text="Hesabım"), "ornek.com.tr")
    assert finding.flags == []


def test_link_text_without_domain_is_not_mismatch():
    finding = inspect_link(Link(href="https://evil.io/x", text="Buraya tıklayın"), "")
    assert "text_mismatch" not in finding.flags


class _FakeSource:
    name = "Sahte"

    def __init__(self, status):
        self.status = status

    async def check(self, url):
        return self.status


def test_reputation_unknown_when_source_down(parsed_fixture):
    _, findings = asyncio.run(
        analyze_urls(parsed_fixture("paypal_evil_link.eml"), [_FakeSource(ScanStatus.UNKNOWN)])
    )
    assert findings[0].reputation == ScanStatus.UNKNOWN


def test_malicious_reputation_adds_signal(parsed_fixture):
    signals, findings = asyncio.run(
        analyze_urls(parsed_fixture("paypal_evil_link.eml"), [_FakeSource(ScanStatus.MALICIOUS)])
    )
    assert findings[0].reputation == ScanStatus.MALICIOUS
    assert "url_reputation_bad" in {signal.name for signal in signals}


def _urlhaus(handler) -> UrlhausClient:
    return UrlhausClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "test-key")


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            httpx.Response(200, json={"query_status": "ok", "threat": "malware_download"}),
            ScanStatus.MALICIOUS,
        ),
        (httpx.Response(200, json={"query_status": "no_results"}), ScanStatus.NOT_LISTED),
        (httpx.Response(429), ScanStatus.UNKNOWN),
        (httpx.Response(500), ScanStatus.ERROR),
    ],
)
def test_urlhaus_statuses(response, expected):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Auth-Key"] == "test-key"
        return response

    assert asyncio.run(_urlhaus(handler).check("http://x.example/")) == expected


def test_urlhaus_does_not_send_fragment():
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        return httpx.Response(200, json={"query_status": "no_results"})

    asyncio.run(_urlhaus(handler).check("https://x.example/a?b=1#token=gizli"))
    assert b"gizli" not in sent[0]
    assert b"b%3D1" in sent[0]


def test_urlhaus_timeout_is_unknown():
    def handler(request):
        raise httpx.ConnectTimeout("zaman aşımı", request=request)

    assert asyncio.run(_urlhaus(handler).check("http://x.example/")) == ScanStatus.UNKNOWN


def test_openphish_feed(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("https://phish.example/login\n", encoding="utf-8")
    source = OpenPhishFeed(feed)
    assert asyncio.run(source.check("https://phish.example/login/")) == ScanStatus.MALICIOUS
    assert asyncio.run(source.check("https://ok.example/")) == ScanStatus.NOT_LISTED
    missing = OpenPhishFeed(tmp_path / "yok.txt")
    assert asyncio.run(missing.check("https://phish.example/login")) == ScanStatus.UNKNOWN
