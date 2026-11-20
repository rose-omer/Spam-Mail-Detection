"""URL analizi. Bağlantılar hiçbir zaman indirilmez; yalnız biçim ve itibar sinyali üretilir."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from spammaild.clients.http import ScanStatus
from spammaild.clients.reputation import UrlReputation
from spammaild.domains import is_ip_literal, registered_domain
from spammaild.parsing import Link, ParsedEmail
from spammaild.scoring import Signal, Source, make_signal

MAX_LINKS = 50
SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rebrand.ly shorturl.at "
    "t.ly tiny.cc s.id rb.gy lnkd.in".split()
)
_DOMAIN_LIKE = re.compile(r"^(?:https?://)?(?:www\.)?[\w.-]+\.[a-z]{2,}(?:/\S*)?$", re.IGNORECASE)


@dataclass(slots=True)
class UrlFinding:
    text: str
    href: str
    host: str
    domain: str
    flags: list[str] = field(default_factory=list)
    reputation: ScanStatus = ScanStatus.SKIPPED


def _host_of(href: str) -> str:
    try:
        return (urlsplit(href).hostname or "").lower()
    except ValueError:
        return ""


def _text_host(text: str) -> str:
    """Bağlantı metni bir adrese benziyorsa o adresin host değerini döner."""
    candidate = text.strip()
    if " " in candidate or not _DOMAIN_LIKE.match(candidate):
        return ""
    if not candidate.lower().startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    return _host_of(candidate)


def inspect_link(link: Link, sender_domain: str) -> UrlFinding:
    host = _host_of(link.href)
    domain = registered_domain(host)
    finding = UrlFinding(text=link.text, href=link.href, host=host, domain=domain)
    if is_ip_literal(host):
        finding.flags.append("ip_literal")
    if "xn--" in host or not host.isascii():
        finding.flags.append("punycode")
    if domain in SHORTENERS or host in SHORTENERS:
        finding.flags.append("shortener")
    text_host = _text_host(link.text)
    if text_host and registered_domain(text_host) != domain:
        finding.flags.append("text_mismatch")
    if sender_domain and domain and domain != sender_domain:
        finding.flags.append("foreign_domain")
    return finding


_FLAG_SIGNALS = {
    "text_mismatch": ("url_text_mismatch", 2.0, "Bağlantı metni {text} gösteriyor; hedef {host}."),
    "ip_literal": ("url_ip_literal", 1.5, "Bağlantı alan adı yerine IP adresine gidiyor ({host})."),
    "punycode": (
        "url_punycode",
        1.5,
        "Bağlantı punycode ya da benzer görünen karakter içeriyor ({host}).",
    ),
    "shortener": ("url_shortener", 1.0, "Bağlantı kısaltıcı servis kullanıyor ({host})."),
    "foreign_domain": (
        "url_foreign_domain",
        1.0,
        "Bağlantı {domain} alan adına gidiyor; gönderen alan adı {sender}.",
    ),
}


async def _check_reputation(findings: list[UrlFinding], sources: list[UrlReputation]) -> None:
    async def check_one(finding: UrlFinding) -> None:
        results = [await source.check(finding.href) for source in sources]
        if ScanStatus.MALICIOUS in results:
            finding.reputation = ScanStatus.MALICIOUS
        elif results and all(result == ScanStatus.NOT_LISTED for result in results):
            finding.reputation = ScanStatus.NOT_LISTED
        elif ScanStatus.ERROR in results:
            finding.reputation = ScanStatus.ERROR
        else:
            finding.reputation = ScanStatus.UNKNOWN

    await asyncio.gather(*(check_one(finding) for finding in findings))


async def analyze_urls(
    parsed: ParsedEmail, reputation_sources: list[UrlReputation]
) -> tuple[list[Signal], list[UrlFinding]]:
    sender_domain = registered_domain(parsed.from_domain)
    findings = [inspect_link(link, sender_domain) for link in parsed.links[:MAX_LINKS]]
    if reputation_sources and findings:
        await _check_reputation(findings, reputation_sources)

    signals: list[Signal] = []
    for flag, (name, score, template) in _FLAG_SIGNALS.items():
        matched = [finding for finding in findings if flag in finding.flags]
        if not matched:
            continue
        first = matched[0]
        reason = template.format(
            text=first.text or first.href,
            host=first.host,
            domain=first.domain,
            sender=parsed.from_domain,
        )
        if len(matched) > 1:
            reason += f" ({len(matched)} bağlantı)"
        signals.append(make_signal(name, score, reason, Source.URL))

    malicious = [finding for finding in findings if finding.reputation == ScanStatus.MALICIOUS]
    if malicious:
        signals.append(
            make_signal(
                "url_reputation_bad",
                2.0,
                f"Bağlantı zararlı URL listesinde: {malicious[0].host}.",
                Source.URL,
            )
        )
    return signals, findings
