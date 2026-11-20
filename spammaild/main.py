"""Uygulama fabrikası.

Çalıştırma: `uvicorn spammaild.main:create_app --factory --host 127.0.0.1 --port 8100`
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException

from spammaild.api.routes import router
from spammaild.api.security import BodySizeLimitMiddleware, RateLimiter
from spammaild.parsing import ParseError
from spammaild.service import Analyzer, build_analyzer
from spammaild.settings import Settings, get_settings

logger = logging.getLogger("spammaild")
WEB_DIR = Path(__file__).resolve().parent / "web"
PANEL_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ]
)
_STATUS_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    413: "PAYLOAD_TOO_LARGE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
}


def _error(status_code: int, message: str, headers: dict | None = None) -> JSONResponse:
    code = _STATUS_CODES.get(status_code, "ERROR")
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
        headers=headers,
    )


def create_app(settings: Settings | None = None, analyzer: Analyzer | None = None) -> FastAPI:
    settings = settings or get_settings()
    if not settings.auth_required and not settings.allow_no_auth:
        raise RuntimeError(
            "API_KEY tanımlı değil. Anahtar verin ya da yalnız yerel geliştirmede "
            "ALLOW_NO_AUTH=true ayarlayın."
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.analyzer = analyzer or build_analyzer(settings)
        if not settings.auth_required:
            logger.warning("ALLOW_NO_AUTH açık: /v1 uç noktaları anahtarsız. Yalnız yerelde.")
        try:
            yield
        finally:
            await app.state.analyzer.aclose()

    app = FastAPI(
        title="SpamMailD",
        version="2.0.0",
        description="E-posta risk analizi. Hiçbir URL indirilmez.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.rate_limiter = RateLimiter(settings.rate_limit_per_minute)
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.max_text_request_bytes,
        path_limits={"/v1/analyze": settings.max_request_bytes},
    )
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=WEB_DIR / "templates")

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return _error(exc.status_code, str(exc.detail), getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(part) for part in first.get("loc", [])[1:])
        message = f"Geçersiz alan: {field}." if field else "İstek doğrulanamadı."
        return _error(422, message)

    @app.exception_handler(ParseError)
    async def parse_error(_: Request, exc: ParseError) -> JSONResponse:
        return _error(422, str(exc))

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Beklenmeyen hata", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "Sunucuda beklenmeyen hata."}},
        )

    @app.get("/health", tags=["sistem"])
    async def health(request: Request) -> dict:
        return {"status": "ok", "model": request.app.state.analyzer.model is not None}

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def panel(request: Request) -> HTMLResponse:
        response = templates.TemplateResponse(request, "index.html", {"version": app.version})
        response.headers["Content-Security-Policy"] = PANEL_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app
