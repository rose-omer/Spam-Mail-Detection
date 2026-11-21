"""`/v1` uç noktaları."""

from __future__ import annotations

from email.errors import HeaderParseError
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.datastructures import UploadFile

from spammaild.api.security import SettingsDep, enforce_rate_limit, require_api_key
from spammaild.parsing import build_text_message
from spammaild.schemas import AnalysisResponse, ConfigOut, ErrorResponse, TextAnalyzeRequest
from spammaild.service import Analyzer

router = APIRouter(prefix="/v1", tags=["analiz"])
protected = [Depends(require_api_key), Depends(enforce_rate_limit)]
ERRORS = {
    401: {"model": ErrorResponse},
    413: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
}


def get_analyzer(request: Request) -> Analyzer:
    return request.app.state.analyzer


AnalyzerDep = Annotated[Analyzer, Depends(get_analyzer)]


@router.get("/config", response_model=ConfigOut)
async def read_config(settings: SettingsDep, analyzer: AnalyzerDep) -> dict:
    names = {scanner.name for scanner in analyzer.file_scanners}
    return {
        "auth_required": settings.auth_required,
        "demo_mode": settings.demo_mode,
        "vt_upload": settings.vt_upload and "VirusTotal" in names,
        "clamav_enabled": "ClamAV" in names,
        "virustotal_enabled": "VirusTotal" in names,
        "url_reputation_enabled": bool(analyzer.url_sources),
        "max_request_mb": settings.max_request_mb,
        "model": analyzer.model_info,
    }


async def _read_raw(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("multipart/form-data"):
        return await request.body()
    form = await request.form()
    upload = form.get("file")
    if isinstance(upload, UploadFile):
        return await upload.read()
    raw = form.get("raw")
    if isinstance(raw, str):
        return raw.encode("utf-8")
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail="Formda `file` (.eml) ya da `raw` (ham mail) alanı yok.",
    )


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    dependencies=protected,
    responses=ERRORS,
    summary="Ham maili ya da .eml dosyasını analiz et",
    openapi_extra={
        "requestBody": {
            "content": {
                "message/rfc822": {"schema": {"type": "string"}},
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "format": "binary"},
                            "raw": {"type": "string"},
                        },
                    }
                },
            }
        }
    },
)
async def analyze(request: Request, analyzer: AnalyzerDep) -> dict:
    """Gövde ham RFC 5322 metni olabilir; multipart formda `file` ya da `raw` alanı da olur.

    Bu uç nokta bağlantıları indirmez. Ekler mailin içinden okunur.
    """
    return await analyzer.analyze(await _read_raw(request))


@router.post(
    "/analyze/text",
    response_model=AnalysisResponse,
    dependencies=protected,
    responses=ERRORS,
    summary="Yalnız düz metni analiz et",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": TextAnalyzeRequest.model_json_schema()}},
        }
    },
)
async def analyze_text(request: Request, analyzer: AnalyzerDep) -> dict:
    # Gövde, kimlik ve hız sınırı denetiminden SONRA okunur (yetkisiz istek gövde okutmaz).
    try:
        payload = TextAnalyzeRequest.model_validate_json(await request.body())
    except ValidationError as exc:
        errors = [{**error, "loc": ("body", *error["loc"])} for error in exc.errors()]
        raise RequestValidationError(errors) from exc
    try:
        raw = build_text_message(payload.text, payload.subject, payload.sender)
    except (HeaderParseError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Gönderen ya da konu alanı geçersiz.",
        ) from exc
    return await analyzer.analyze(raw)
