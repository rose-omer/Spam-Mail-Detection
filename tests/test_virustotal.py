import asyncio
import hashlib

import httpx
import pytest

from spammaild.clients.http import ScanStatus
from spammaild.clients.scanners import VirusTotalScanner

DATA = b"ornek ek icerigi"
DIGEST = hashlib.sha256(DATA).hexdigest()


def _scanner(handler, allow_upload=False) -> VirusTotalScanner:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return VirusTotalScanner(
        client, "test-key", allow_upload=allow_upload, poll_attempts=2, poll_interval_s=0
    )


def _report(**stats) -> httpx.Response:
    return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_report(malicious=3, suspicious=0, harmless=60, undetected=10), ScanStatus.INFECTED),
        (_report(malicious=0, suspicious=1, harmless=60), ScanStatus.INFECTED),
        (_report(malicious=0, suspicious=0, harmless=60, undetected=10), ScanStatus.CLEAN),
        (_report(malicious=0, suspicious=0), ScanStatus.UNKNOWN),
        (httpx.Response(429), ScanStatus.UNKNOWN),
        (httpx.Response(401), ScanStatus.ERROR),
        (httpx.Response(500), ScanStatus.ERROR),
        (httpx.Response(200, json={"beklenmeyen": True}), ScanStatus.ERROR),
    ],
)
def test_hash_lookup_statuses(response, expected):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path.endswith(f"/files/{DIGEST}")
        assert request.headers["x-apikey"] == "test-key"
        return response

    result = asyncio.run(_scanner(handler).scan(DATA))
    assert result.status == expected


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectTimeout])
def test_timeout_is_unknown_not_clean(error):
    def handler(request):
        raise error("zaman aşımı", request=request)

    result = asyncio.run(_scanner(handler).scan(DATA))
    assert result.status == ScanStatus.UNKNOWN


def test_connection_error_is_error_not_clean():
    def handler(request):
        raise httpx.ConnectError("bağlantı yok", request=request)

    assert asyncio.run(_scanner(handler).scan(DATA)).status == ScanStatus.ERROR


def test_not_found_does_not_upload_by_default():
    calls: list[str] = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(404)

    result = asyncio.run(_scanner(handler).scan(DATA))
    assert result.status == ScanStatus.UNKNOWN
    assert calls == ["GET"]


def _upload_handler(calls: list[str], analysis: httpx.Response):
    def handler(request):
        calls.append(f"{request.method} {request.url.path.removeprefix('/api/v3/').split('/')[0]}")
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "analiz-1"}})
        if request.url.path.endswith("/analyses/analiz-1"):
            return analysis
        return httpx.Response(404)

    return handler


def _analysis(status: str, **stats) -> httpx.Response:
    return httpx.Response(200, json={"data": {"attributes": {"status": status, "stats": stats}}})


def test_not_found_uploads_only_when_allowed_and_pending_stays_unknown():
    calls: list[str] = []
    handler = _upload_handler(calls, _analysis("queued"))
    result = asyncio.run(_scanner(handler, allow_upload=True).scan(DATA))
    assert calls == ["GET files", "POST files", "GET analyses", "GET analyses"]  # en çok 2
    assert result.status == ScanStatus.UNKNOWN  # bitmeyen analiz "clean" değildir


@pytest.mark.parametrize(
    ("analysis", "expected"),
    [
        (_analysis("completed", malicious=2, harmless=50), ScanStatus.INFECTED),
        (_analysis("completed", malicious=0, suspicious=0, harmless=50), ScanStatus.CLEAN),
        (httpx.Response(500), ScanStatus.ERROR),
        (httpx.Response(200, json={"beklenmeyen": True}), ScanStatus.ERROR),
    ],
)
def test_upload_waits_for_analysis_result(analysis, expected):
    calls: list[str] = []
    result = asyncio.run(_scanner(_upload_handler(calls, analysis), allow_upload=True).scan(DATA))
    assert result.status == expected
    assert calls[:3] == ["GET files", "POST files", "GET analyses"]
