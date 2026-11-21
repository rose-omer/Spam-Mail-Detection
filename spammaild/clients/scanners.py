"""Dosya tarayıcıları: clamd (INSTREAM) ve VirusTotal (önce hash sorgusu).

Hiçbir hata durumu `clean` sonucu üretmez. `clean` yalnız tamamlanmış analizden gelir.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Protocol

import httpx

from spammaild.clients.http import ScanStatus, status_for_http_error

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
VT_UPLOAD_LIMIT = 32 * 1024 * 1024
CLAMD_CHUNK = 64 * 1024


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: ScanStatus
    detail: str = ""


class FileScanner(Protocol):
    name: str

    async def scan(self, data: bytes) -> ScanResult: ...


class ClamdScanner:
    """clamd TCP INSTREAM istemcisi. İmza veritabanı clamd içinde bir kez yüklenir."""

    name = "ClamAV"

    def __init__(self, host: str, port: int = 3310, timeout: float = 30.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    async def scan(self, data: bytes) -> ScanResult:
        try:
            reply = await asyncio.wait_for(self._instream(data), timeout=self._timeout)
        except TimeoutError:
            return ScanResult(ScanStatus.ERROR, "clamd zaman aşımı")
        except OSError as exc:
            logger.warning("clamd erişilemedi: %s", exc)
            return ScanResult(ScanStatus.ERROR, "clamd erişilemedi")
        return parse_clamd_reply(reply)

    async def _instream(self, data: bytes) -> str:
        reader, writer = await asyncio.open_connection(self._host, self._port)
        try:
            writer.write(b"zINSTREAM\0")
            for start in range(0, len(data), CLAMD_CHUNK):
                chunk = data[start : start + CLAMD_CHUNK]
                writer.write(struct.pack("!L", len(chunk)) + chunk)
                await writer.drain()
            writer.write(struct.pack("!L", 0))
            await writer.drain()
            reply = await reader.readuntil(b"\0")
        finally:
            writer.close()
        return reply.rstrip(b"\0").decode("utf-8", errors="replace")


def parse_clamd_reply(reply: str) -> ScanResult:
    """`stream: OK`, `stream: <imza> FOUND` ya da `... ERROR` yanıtını çözer."""
    body = reply.partition(": ")[2] if ": " in reply else reply
    if body == "OK":
        return ScanResult(ScanStatus.CLEAN)
    if body.endswith(" FOUND"):
        return ScanResult(ScanStatus.INFECTED, body.removesuffix(" FOUND"))
    return ScanResult(ScanStatus.ERROR, body or "boş yanıt")


class VirusTotalScanner:
    """Önce `GET /files/{sha256}`. Kayıt yoksa ve `allow_upload` açıksa dosyayı yükler,
    sonra analiz sonucunu en çok `poll_attempts` kez sorar."""

    name = "VirusTotal"

    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        allow_upload: bool = False,
        poll_attempts: int = 3,
        poll_interval_s: float = 5.0,
    ):
        self._client = client
        self._headers = {"x-apikey": api_key}
        self._allow_upload = allow_upload
        self._poll_attempts = poll_attempts
        self._poll_interval_s = poll_interval_s

    async def scan(self, data: bytes) -> ScanResult:
        digest = hashlib.sha256(data).hexdigest()
        try:
            response = await self._client.get(f"{VT_BASE}/files/{digest}", headers=self._headers)
            if response.status_code == 404:
                return await self._not_found(data)
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
            logger.warning("VirusTotal sorgusu başarısız: %s", type(exc).__name__)
            if isinstance(exc, httpx.HTTPError):
                return ScanResult(status_for_http_error(exc), "VirusTotal yanıt vermedi")
            return ScanResult(ScanStatus.ERROR, "VirusTotal yanıtı okunamadı")
        return _result_from_stats(stats)

    async def _not_found(self, data: bytes) -> ScanResult:
        if not self._allow_upload:
            return ScanResult(ScanStatus.UNKNOWN, "VirusTotal'da kayıt yok; dosya yüklenmedi")
        if len(data) > VT_UPLOAD_LIMIT:
            return ScanResult(ScanStatus.UNKNOWN, "dosya 32 MB yükleme sınırını aşıyor")
        try:
            response = await self._client.post(
                f"{VT_BASE}/files", headers=self._headers, files={"file": ("ek", data)}
            )
            response.raise_for_status()
            analysis_id = str(response.json()["data"]["id"])
        except httpx.HTTPError as exc:
            return ScanResult(status_for_http_error(exc), "VirusTotal yüklemesi başarısız")
        except (KeyError, ValueError, TypeError):
            return ScanResult(ScanStatus.UNKNOWN, "dosya yüklendi; analiz kimliği okunamadı")
        return await self._wait_for_analysis(analysis_id)

    async def _wait_for_analysis(self, analysis_id: str) -> ScanResult:
        """`GET /analyses/{id}` sonucunu sınırlı sayıda sorar. Bitmezse `unknown` döner."""
        for _ in range(self._poll_attempts):
            await asyncio.sleep(self._poll_interval_s)  # VT analizi birkaç saniye sürer
            try:
                response = await self._client.get(
                    f"{VT_BASE}/analyses/{analysis_id}", headers=self._headers
                )
                response.raise_for_status()
                attributes = response.json()["data"]["attributes"]
            except httpx.HTTPError as exc:
                return ScanResult(status_for_http_error(exc), "VirusTotal analiz sorgusu başarısız")
            except (KeyError, ValueError, TypeError):
                return ScanResult(ScanStatus.ERROR, "VirusTotal analiz yanıtı okunamadı")
            if attributes.get("status") == "completed":
                return _result_from_stats(attributes.get("stats") or {})
        return ScanResult(ScanStatus.UNKNOWN, "dosya yüklendi; analiz süresinde bitmedi")


def _result_from_stats(stats: dict) -> ScanResult:
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    if flagged > 0:
        return ScanResult(ScanStatus.INFECTED, f"{flagged} motor zararlı buldu")
    if sum(int(value) for value in stats.values()) == 0:
        return ScanResult(ScanStatus.UNKNOWN, "analiz sonucu yok")
    return ScanResult(ScanStatus.CLEAN)
