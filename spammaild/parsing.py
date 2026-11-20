"""Ham RFC 5322 maili ayrıştırır. Ağa hiçbir istek atmaz."""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]+", re.IGNORECASE)
_SKIP_TAGS = {"script", "style", "head", "title"}
_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "section"}


class ParseError(ValueError):
    """Girdi bir e-posta olarak okunamıyor."""


@dataclass(frozen=True, slots=True)
class Link:
    href: str
    text: str = ""
    source: str = "text"  # "html" ya da "text"


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str
    content_type: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(slots=True)
class ParsedEmail:
    message: EmailMessage
    from_address: str = ""
    from_display: str = ""
    subject: str = ""
    text: str = ""
    html: str | None = None
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_address.rpartition("@")[2].lower() if "@" in self.from_address else ""


class _HtmlExtractor(HTMLParser):
    """HTML'den görünen metni ve `<a href>` bağlantılarını çıkarır."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href") or ""
            self._href = href.strip()
            self._anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a" and self._href is not None:
            if self._href.lower().startswith(("http://", "https://")):
                text = " ".join("".join(self._anchor_text).split())
                self.links.append(Link(href=self._href, text=text, source="html"))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def text(self) -> str:
        joined = "".join(self.parts)
        lines = (" ".join(line.split()) for line in joined.splitlines())
        return "\n".join(line for line in lines if line)


def html_to_text(html: str) -> tuple[str, list[Link]]:
    extractor = _HtmlExtractor()
    extractor.feed(html)
    extractor.close()
    return extractor.text(), extractor.links


def extract_text_links(text: str) -> list[Link]:
    return [Link(href=match.rstrip(".,;:!?"), source="text") for match in URL_RE.findall(text)]


def _decode_text_part(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
    return content if isinstance(content, str) else content.decode("utf-8", errors="replace")


def _collect_attachments(message: EmailMessage) -> list[Attachment]:
    attachments: list[Attachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not (part.is_attachment() or filename):
            continue
        data = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=filename or "adsiz",
                content_type=part.get_content_type(),
                data=data,
            )
        )
    return attachments


def _unique_links(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    result: list[Link] = []
    for link in links:
        key = (link.href, link.text)
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def parse_email(raw: bytes) -> ParsedEmail:
    if not raw or not raw.strip():
        raise ParseError("Boş girdi. Ham maili ya da .eml dosyasını gönderin.")
    message = email.message_from_bytes(raw, policy=policy.default)
    if not isinstance(message, EmailMessage):  # policy.default her zaman EmailMessage döner
        raise ParseError("Mail ayrıştırılamadı.")

    display, address = parseaddr(str(message.get("From", "")))
    parsed = ParsedEmail(
        message=message,
        from_address=address.lower(),
        from_display=display,
        subject=str(message.get("Subject", "") or ""),
    )

    plain_part = message.get_body(preferencelist=("plain",))
    html_part = message.get_body(preferencelist=("html",))
    links: list[Link] = []
    if html_part is not None:
        parsed.html = _decode_text_part(html_part)
        html_text, html_links = html_to_text(parsed.html)
        links.extend(html_links)
        parsed.text = html_text
    if plain_part is not None:
        parsed.text = _decode_text_part(plain_part)
    if plain_part is None and html_part is None and not message.is_multipart():
        parsed.text = _decode_text_part(message)

    html_hrefs = {link.href for link in links}
    links.extend(link for link in extract_text_links(parsed.text) if link.href not in html_hrefs)
    parsed.links = _unique_links(links)
    parsed.attachments = _collect_attachments(message)
    if not (parsed.text.strip() or parsed.attachments or parsed.from_address or parsed.subject):
        # Skorlanamayan girdi "temiz" sayılmaz (fail-closed).
        raise ParseError("Girdi bir e-posta gibi görünmüyor: gövde, konu, gönderen ve ek yok.")
    return parsed


def build_text_message(text: str, subject: str = "", sender: str = "") -> bytes:
    """Düz metinden en küçük RFC 5322 mesajını kurar (`/v1/analyze/text` için)."""
    message = EmailMessage()
    if sender:
        message["From"] = sender
    if subject:
        message["Subject"] = subject
    message.set_content(text)
    return message.as_bytes()
