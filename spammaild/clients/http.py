"""Dış servis istemcileri için ortak durum adları ve hata eşlemesi."""

from __future__ import annotations

from enum import StrEnum

import httpx


class ScanStatus(StrEnum):
    CLEAN = "clean"  # analiz tamamlandı, bulgu yok
    INFECTED = "infected"  # zararlı bulundu
    MALICIOUS = "malicious"  # URL itibar listesinde
    NOT_LISTED = "not_listed"  # URL listede yok
    UNKNOWN = "unknown"  # sonuç yok: kota, zaman aşımı, kayıt yok
    ERROR = "error"  # servis hata verdi ya da erişilemedi
    SKIPPED = "skipped"  # ayar kapalı ya da demo modu


def status_for_http_error(exc: Exception) -> ScanStatus:
    """Ağ ve HTTP hatalarını duruma çevirir. Hiçbir hata `clean` sonucu üretmez."""
    if isinstance(exc, httpx.TimeoutException):
        return ScanStatus.UNKNOWN
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
        return ScanStatus.UNKNOWN
    return ScanStatus.ERROR
