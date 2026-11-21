"""API istek ve yanıt şemaları."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TextAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    subject: str = Field(default="", max_length=1_000)
    sender: str = Field(default="", max_length=320)


class Reason(BaseModel):
    source: str
    name: str
    text: str
    impact: float
    status: str


class AuthCheckOut(BaseModel):
    result: str
    source: str


class AuthOut(BaseModel):
    spf: AuthCheckOut
    dkim: AuthCheckOut
    dmarc: AuthCheckOut
    trusted_authserv_id: str


class UrlOut(BaseModel):
    text: str
    href: str
    host: str
    domain: str
    flags: list[str]
    reputation: str


class ScanOut(BaseModel):
    status: str
    detail: str = ""


class AttachmentOut(BaseModel):
    filename: str
    content_type: str
    detected_type: str
    size: int
    sha256: str
    flags: list[str]
    clamav: ScanOut
    virustotal: ScanOut


class MessageOut(BaseModel):
    sender: str
    sender_name: str
    subject: str
    language: str


class ModelOut(BaseModel):
    name: str
    version: str
    backend: str
    available: bool


class AnalysisResponse(BaseModel):
    risk: int = Field(ge=0, le=100)
    band: str
    reasons: list[Reason] = Field(min_length=1)
    auth: AuthOut
    urls: list[UrlOut]
    attachments: list[AttachmentOut]
    message: MessageOut
    model: ModelOut


class ConfigOut(BaseModel):
    auth_required: bool
    demo_mode: bool
    vt_upload: bool
    clamav_enabled: bool
    virustotal_enabled: bool
    url_reputation_enabled: bool
    max_request_mb: float
    model: ModelOut


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
