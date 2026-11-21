"""Güvenlik katmanı: API anahtarı, istek gövdesi sınırı ve bellek içi hız sınırı."""

from __future__ import annotations

import hmac
import time
from collections import deque
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from spammaild.settings import Settings


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


SettingsDep = Annotated[Settings, Depends(get_app_settings)]


async def require_api_key(
    settings: SettingsDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    if not settings.auth_required:
        return
    expected = settings.api_key.get_secret_value() if settings.api_key else ""
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçerli bir X-API-Key başlığı gerekli.",
        )


class RateLimiter:
    """İstemci başına kayan pencere sayacı. Tek süreçli kurulum içindir.

    Süresi dolan kovalar her `sweep_every` çağrıda silinir; adres sayısı bellek büyütmez.
    İstemci adresi `request.client.host` değeridir. Ters vekil arkasında uvicorn
    `--proxy-headers --forwarded-allow-ips` ile çalıştırılmalıdır.
    """

    def __init__(self, limit_per_minute: int, window_s: float = 60.0, sweep_every: int = 256):
        self.limit = limit_per_minute
        self.window_s = window_s
        self.sweep_every = sweep_every
        self._hits: dict[str, deque[float]] = {}
        self._calls = 0

    def __len__(self) -> int:
        return len(self._hits)

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic() if now is None else now
        self._calls += 1
        if self._calls % self.sweep_every == 0:
            self._sweep(now)
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def _sweep(self, now: float) -> None:
        expired = [
            key for key, hits in self._hits.items() if not hits or now - hits[-1] >= self.window_s
        ]
        for key in expired:
            del self._hits[key]


async def enforce_rate_limit(request: Request) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    client = request.client.host if request.client else "anon"
    if not limiter.allow(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Çok fazla istek. Bir dakika sonra yeniden deneyin.",
            headers={"Retry-After": "60"},
        )


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Gövde sınırını hem Content-Length başlığında hem akan veride uygular.

    `max_bytes` varsayılan sınırdır. `path_limits` belirli yollara ayrı sınır verir
    (ör. yalnız ekli ham mailin geldiği `/v1/analyze` için büyük sınır).
    """

    def __init__(
        self, app: ASGIApp, max_bytes: int, path_limits: dict[str, int] | None = None
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.path_limits = path_limits or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.path_limits.get(scope.get("path", "").rstrip("/"), self.max_bytes)
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await self._reject(send, limit)
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if not response_started:
                await self._reject(send, limit)

    async def _reject(self, send: Send, limit: int) -> None:
        mb = limit / (1024 * 1024)
        body = (
            '{"error":{"code":"PAYLOAD_TOO_LARGE","message":"İstek gövdesi '
            f'{mb:.0f} MB sınırını aşıyor."}}}}'
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
