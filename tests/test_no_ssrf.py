"""`/v1/analyze` dışarıya hiçbir ağ isteği atmamalı (URL indirme yok, SSRF yok)."""

import asyncio
import socket

import pytest

from spammaild.service import build_analyzer
from tests.conftest import make_settings


@pytest.fixture
def block_network(monkeypatch):
    """Ağ çağrılarını yasaklayan anahtar. İstemci kurulduktan sonra açılır.

    Windows'ta olay döngüsü kurulurken `socketpair` yerel bağlantı açar; bu yüzden
    yasak döngü kurulduktan sonra devreye girer.
    """
    attempts: list[str] = []

    def blocked(*args, **kwargs):
        attempts.append(repr(args[:2]))
        raise OSError("Testte ağ erişimi yasak")

    async def blocked_async(*args, **kwargs):
        blocked(*args, **kwargs)

    def enable() -> list[str]:
        monkeypatch.setattr(socket, "create_connection", blocked)
        monkeypatch.setattr(socket, "getaddrinfo", blocked)
        monkeypatch.setattr(socket.socket, "connect", blocked)
        monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", blocked_async)
        monkeypatch.setattr(asyncio, "open_connection", blocked_async)
        return attempts

    return enable


@pytest.mark.parametrize(
    "name", ["paypal_evil_link.eml", "href_mismatch.eml", "punycode.eml", "double_extension.eml"]
)
def test_demo_mode_analysis_makes_no_connection(make_client, fixture_bytes, block_network, name):
    client = make_client()  # TestClient bellek içi taşıma kullanır; soket açmaz
    attempts = block_network()
    response = client.post("/v1/analyze", content=fixture_bytes(name))
    assert response.status_code == 200
    assert response.json()["reasons"]
    assert attempts == []


def test_build_analyzer_in_demo_mode_has_no_external_clients():
    analyzer = build_analyzer(
        make_settings(demo_mode=True, clamd_host="clamav", vt_api_key="x", urlhaus_auth_key="y")
    )
    assert analyzer.file_scanners == []
    assert analyzer.url_sources == []
    assert analyzer.http is None


def test_without_keys_no_external_clients():
    analyzer = build_analyzer(make_settings(demo_mode=False))
    assert analyzer.file_scanners == []
    assert analyzer.url_sources == []
