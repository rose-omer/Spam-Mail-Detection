"""Kimlik doğrulama analizi.

Yalnız en üstteki `Authentication-Results` başlığı okunur ve onun `authserv-id` değeri
güvenilen sunucu olmalıdır. Gövdede ya da başka başlıkta geçen `spf=pass` metni yok sayılır.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import authres

from spammaild.analyzers.content import fold_turkish
from spammaild.domains import registered_domain
from spammaild.parsing import ParsedEmail
from spammaild.scoring import Signal, Source, make_signal

logger = logging.getLogger(__name__)

METHODS = ("spf", "dkim", "dmarc")
_KNOWN_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}

# Marka adı → markanın kullandığı kayıtlı alan adları.
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.com.tr"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "microsoft": frozenset({"microsoft.com", "outlook.com", "live.com", "office.com"}),
    "google": frozenset({"google.com", "gmail.com", "youtube.com"}),
    "amazon": frozenset({"amazon.com", "amazon.com.tr", "amazon.de"}),
    "netflix": frozenset({"netflix.com"}),
    "garanti": frozenset({"garantibbva.com.tr", "garanti.com.tr"}),
    "akbank": frozenset({"akbank.com"}),
    "ziraat": frozenset({"ziraatbank.com.tr", "ziraat.com.tr"}),
    "is bankasi": frozenset({"isbank.com.tr"}),
    "yapi kredi": frozenset({"yapikredi.com.tr"}),
    "e-devlet": frozenset({"turkiye.gov.tr"}),
    "ptt": frozenset({"ptt.gov.tr"}),
    "turkcell": frozenset({"turkcell.com.tr"}),
    "trendyol": frozenset({"trendyol.com", "trendyolmail.com"}),
    "hepsiburada": frozenset({"hepsiburada.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
}


@dataclass(slots=True)
class AuthCheck:
    result: str = "unknown"  # pass / fail / softfail / neutral / none / unknown ...
    source: str = ""  # sonucun okunduğu başlık


@dataclass(slots=True)
class AuthReport:
    spf: AuthCheck = field(default_factory=AuthCheck)
    dkim: AuthCheck = field(default_factory=AuthCheck)
    dmarc: AuthCheck = field(default_factory=AuthCheck)
    dkim_domain: str = ""
    trusted_header_found: bool = False


def _parse_header(value: str) -> authres.AuthenticationResultsHeader | None:
    try:
        return authres.AuthenticationResultsHeader.parse(f"Authentication-Results: {value}")
    except (authres.AuthResError, ValueError, IndexError) as exc:
        logger.info("Authentication-Results ayrıştırılamadı: %s", exc)
        return None


def _property(result: authres.AuthenticationResult, ptype: str, name: str) -> str:
    for prop in result.properties:
        if prop.type == ptype and prop.name == name:
            return str(prop.value)
    return ""


def read_trusted_results(parsed: ParsedEmail, trusted_authserv_id: str) -> AuthReport:
    report = AuthReport()
    if not trusted_authserv_id:
        return report
    headers = parsed.message.get_all("Authentication-Results") or []
    if not headers:
        return report
    # Yalnız en üstteki başlık okunur (listede ilk sırada). Alıcı sunucu kendi başlığını
    # en üste ekler; alttaki başlıklar yolda ya da saldırgan tarafından eklenmiş olabilir.
    # Üstteki başlık güvenilen sunucudan değilse alttaki "güvenilen" kopya da yok sayılır.
    header = _parse_header(str(headers[0]))
    if header is None or str(header.authserv_id).lower() != trusted_authserv_id.lower():
        return report
    report.trusted_header_found = True
    source = f"Authentication-Results: {header.authserv_id}"
    for result in header.results:
        method = str(result.method).lower()
        if method not in METHODS:
            continue
        check: AuthCheck = getattr(report, method)
        if check.result != "unknown":
            continue  # aynı yöntemin ilk sonucu geçerli
        value = str(result.result).lower()
        check.result = value if value in _KNOWN_RESULTS else "unknown"
        check.source = source
        if method == "dkim" and value == "pass":
            identity = _property(result, "header", "d") or _property(result, "header", "i")
            report.dkim_domain = identity.lstrip("@").rpartition("@")[2].lower()
    return report


def _display_name_spoof(parsed: ParsedEmail) -> Signal | None:
    display = fold_turkish(parsed.from_display)
    if not display:
        return None
    sender_domain = registered_domain(parsed.from_domain)
    for brand, domains in BRANDS.items():
        if brand in display and sender_domain not in domains:
            return make_signal(
                "display_name_spoof",
                2.0,
                f"Gönderen adı “{parsed.from_display}” bir markayı anıyor; "
                f"ama adres {parsed.from_domain or 'bilinmiyor'} alan adından geliyor.",
                Source.AUTH,
            )
    return None


def analyze_auth(parsed: ParsedEmail, trusted_authserv_id: str) -> tuple[list[Signal], AuthReport]:
    report = read_trusted_results(parsed, trusted_authserv_id)
    signals: list[Signal] = []

    if not trusted_authserv_id:
        signals.append(
            make_signal(
                "auth_untrusted",
                0.0,
                "TRUSTED_AUTHSERV_ID tanımlı değil; SPF, DKIM ve DMARC sonuçları okunmadı.",
                Source.AUTH,
                status="unknown",
            )
        )
    elif not report.trusted_header_found:
        has_any = bool(parsed.message.get_all("Authentication-Results"))
        reason = (
            "Authentication-Results başlığı güvenilen sunucudan gelmiyor; sonuçlar yok sayıldı."
            if has_any
            else "Güvenilen sunucunun Authentication-Results başlığı yok."
        )
        signals.append(make_signal("auth_untrusted", 1.0, reason, Source.AUTH, status="unknown"))
    else:
        results = {method: getattr(report, method).result for method in METHODS}
        if results["spf"] in {"fail", "softfail"}:
            signals.append(
                make_signal("auth_spf_fail", 1.0, f"SPF sonucu: {results['spf']}.", Source.AUTH)
            )
        if results["dkim"] == "fail":
            signals.append(
                make_signal("auth_dkim_fail", 1.0, "DKIM imzası doğrulanmadı.", Source.AUTH)
            )
        if results["dmarc"] == "fail":
            signals.append(
                make_signal("auth_dmarc_fail", 2.0, "DMARC denetimi başarısız.", Source.AUTH)
            )
        if all(value == "pass" for value in results.values()):
            signals.append(
                make_signal(
                    "auth_all_pass",
                    -1.0,
                    "SPF, DKIM ve DMARC güvenilen sunucuda geçti.",
                    Source.AUTH,
                )
            )
        if report.dkim_domain and parsed.from_domain:
            if registered_domain(report.dkim_domain) != registered_domain(parsed.from_domain):
                signals.append(
                    make_signal(
                        "auth_dkim_misaligned",
                        1.0,
                        f"DKIM imzası {report.dkim_domain} alan adına ait; "
                        f"gönderen {parsed.from_domain}.",
                        Source.AUTH,
                    )
                )

    spoof = _display_name_spoof(parsed)
    if spoof is not None:
        signals.append(spoof)
    return signals, report
