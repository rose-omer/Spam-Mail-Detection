"""URL itibar kaynakları: URLhaus API ve yerel OpenPhish feed dosyası. URL indirilmez."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol
from urllib.parse import urldefrag

import httpx

from spammaild.clients.http import ScanStatus, status_for_http_error

logger = logging.getLogger(__name__)

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


class UrlReputation(Protocol):
    name: str

    async def check(self, url: str) -> ScanStatus: ...


class UrlhausClient:
    name = "URLhaus"

    def __init__(self, client: httpx.AsyncClient, auth_key: str) -> None:
        self._client = client
        self._auth_key = auth_key

    async def check(self, url: str) -> ScanStatus:
        # Fragment (#...) sunucuya hiç gitmez ve listede eşleşmeyi etkilemez; gönderilmez.
        # Sorgu kısmı korunur: URLhaus tam URL eşler. Panel bunu kullanıcıya bildirir.
        try:
            response = await self._client.post(
                URLHAUS_ENDPOINT,
                data={"url": urldefrag(url).url},
                headers={"Auth-Key": self._auth_key},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("URLhaus sorgusu başarısız: %s", type(exc).__name__)
            return status_for_http_error(exc)
        query_status = payload.get("query_status")
        if query_status == "ok":
            return ScanStatus.MALICIOUS
        if query_status == "no_results":
            return ScanStatus.NOT_LISTED
        return ScanStatus.UNKNOWN


class OpenPhishFeed:
    """OpenPhish community feed'inin yerel kopyası. Dosyayı ayrı bir iş günceller."""

    name = "OpenPhish"

    def __init__(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("OpenPhish feed okunamadı: %s", exc)
            lines = []
        self._urls = {line.strip().rstrip("/") for line in lines if line.strip()}
        self.available = bool(self._urls)

    async def check(self, url: str) -> ScanStatus:
        if not self.available:
            return ScanStatus.UNKNOWN
        return ScanStatus.MALICIOUS if url.rstrip("/") in self._urls else ScanStatus.NOT_LISTED
