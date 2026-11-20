"""Analiz hattı: ayrıştırma → dört analiz → skor. Bir analiz hata verirse diğerleri sürer."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

from spammaild.analyzers.attachments import AttachmentFinding, analyze_attachments
from spammaild.analyzers.auth import AuthReport, analyze_auth
from spammaild.analyzers.content import (
    ContentModel,
    ContentResult,
    ModelUnavailableError,
    analyze_content,
    load_content_model,
)
from spammaild.analyzers.urls import UrlFinding, analyze_urls
from spammaild.clients.http import ScanStatus
from spammaild.clients.reputation import OpenPhishFeed, UrlhausClient, UrlReputation
from spammaild.clients.scanners import ClamdScanner, FileScanner, ScanResult, VirusTotalScanner
from spammaild.parsing import ParsedEmail, parse_email
from spammaild.scoring import Signal, Source, combine, make_signal
from spammaild.settings import Settings

logger = logging.getLogger(__name__)
_SKIPPED = ScanResult(ScanStatus.SKIPPED)


@dataclass(slots=True)
class Analyzer:
    settings: Settings
    model: ContentModel | None = None
    file_scanners: list[FileScanner] = field(default_factory=list)
    url_sources: list[UrlReputation] = field(default_factory=list)
    http: httpx.AsyncClient | None = None

    @property
    def model_info(self) -> dict:
        return {
            "name": getattr(self.model, "name", self.settings.model_backend),
            "version": getattr(self.model, "version", "-"),
            "backend": self.settings.model_backend,
            "available": self.model is not None,
        }

    async def aclose(self) -> None:
        if self.http is not None:
            await self.http.aclose()

    async def analyze(self, raw: bytes) -> dict:
        parsed = parse_email(raw)
        signals: list[Signal] = []

        content_result: ContentResult | None = None
        try:
            content_signals, content_result = analyze_content(
                self.model, parsed.text, parsed.subject
            )
            signals += content_signals
        except Exception:  # bir analizin hatası diğerlerini durdurmaz
            logger.exception("İçerik analizi hata verdi")
            signals.append(_error_signal("content_model", Source.CONTENT, "İçerik analizi"))

        auth_report = AuthReport()
        try:
            auth_signals, auth_report = analyze_auth(parsed, self.settings.trusted_authserv_id)
            signals += auth_signals
        except Exception:
            logger.exception("Kimlik analizi hata verdi")
            signals.append(_error_signal("auth_untrusted", Source.AUTH, "Kimlik analizi"))

        url_findings: list[UrlFinding] = []
        try:
            url_signals, url_findings = await analyze_urls(parsed, self.url_sources)
            signals += url_signals
        except Exception:
            logger.exception("URL analizi hata verdi")
            signals.append(_error_signal("url_text_mismatch", Source.URL, "URL analizi"))

        attachment_findings: list[AttachmentFinding] = []
        try:
            attachment_signals, attachment_findings = await analyze_attachments(
                parsed.attachments,
                self.file_scanners,
                self.settings.max_attachment_bytes,
                self.settings.max_total_attachment_bytes,
            )
            signals += attachment_signals
        except Exception:
            logger.exception("Ek analizi hata verdi")
            signals.append(
                _error_signal("attachment_scan_unknown", Source.ATTACHMENT, "Ek analizi")
            )

        verdict = combine(signals)
        return {
            "risk": verdict.risk,
            "band": str(verdict.band),
            "reasons": [
                {
                    "source": str(signal.source),
                    "name": signal.name,
                    "text": signal.reason,
                    "impact": round(signal.impact, 2),
                    "status": signal.status,
                }
                for signal in verdict.signals
            ],
            "auth": _auth_out(auth_report, self.settings.trusted_authserv_id),
            "urls": [_url_out(finding) for finding in url_findings],
            "attachments": [_attachment_out(finding) for finding in attachment_findings],
            "message": _message_out(parsed, content_result),
            "model": self.model_info,
        }


def _error_signal(name: str, source: Source, label: str) -> Signal:
    return make_signal(name, 0.0, f"{label} hata verdi; bu bölüm puanlanmadı.", source, "error")


def _auth_out(report: AuthReport, trusted: str) -> dict:
    return {
        "spf": {"result": report.spf.result, "source": report.spf.source},
        "dkim": {"result": report.dkim.result, "source": report.dkim.source},
        "dmarc": {"result": report.dmarc.result, "source": report.dmarc.source},
        "trusted_authserv_id": trusted,
    }


def _url_out(finding: UrlFinding) -> dict:
    return {
        "text": finding.text,
        "href": finding.href,
        "host": finding.host,
        "domain": finding.domain,
        "flags": finding.flags,
        "reputation": str(finding.reputation),
    }


def _scan_out(result: ScanResult) -> dict:
    return {"status": str(result.status), "detail": result.detail}


def _attachment_out(finding: AttachmentFinding) -> dict:
    return {
        "filename": finding.filename,
        "content_type": finding.content_type,
        "detected_type": finding.detected_type,
        "size": finding.size,
        "sha256": finding.sha256,
        "flags": finding.flags,
        "clamav": _scan_out(finding.scans.get("ClamAV", _SKIPPED)),
        "virustotal": _scan_out(finding.scans.get("VirusTotal", _SKIPPED)),
    }


def _message_out(parsed: ParsedEmail, content: ContentResult | None) -> dict:
    return {
        "sender": parsed.from_address,
        "sender_name": parsed.from_display,
        "subject": parsed.subject,
        "language": content.language if content else "unknown",
    }


def build_analyzer(settings: Settings) -> Analyzer:
    """Ayarlara göre modeli ve dış istemcileri kurar. Demo modunda dış servis yoktur."""
    try:
        model: ContentModel | None = load_content_model(settings.model_backend, settings.model_path)
    except ModelUnavailableError as exc:
        logger.error("İçerik modeli yüklenemedi: %s", exc)
        model = None

    analyzer = Analyzer(settings=settings, model=model)
    if settings.demo_mode:
        return analyzer

    needs_http = bool(settings.vt_api_key or settings.urlhaus_auth_key)
    if needs_http:
        analyzer.http = httpx.AsyncClient(
            timeout=settings.external_timeout_s, follow_redirects=False
        )
    if settings.clamd_host:
        analyzer.file_scanners.append(ClamdScanner(settings.clamd_host, settings.clamd_port))
    if settings.vt_api_key and analyzer.http is not None:
        analyzer.file_scanners.append(
            VirusTotalScanner(
                analyzer.http,
                settings.vt_api_key.get_secret_value(),
                settings.vt_upload,
                poll_attempts=settings.vt_poll_attempts,
                poll_interval_s=settings.vt_poll_interval_s,
            )
        )
    if settings.urlhaus_auth_key and analyzer.http is not None:
        analyzer.url_sources.append(
            UrlhausClient(analyzer.http, settings.urlhaus_auth_key.get_secret_value())
        )
    if settings.openphish_feed_path:
        analyzer.url_sources.append(OpenPhishFeed(settings.openphish_feed_path))
    return analyzer
