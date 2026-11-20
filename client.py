"""SpamMailD ince istemcisi.

Komutlar:
    python client.py fetch --limit 5      # IMAP'ten okunmamış mailleri çeker, "okundu" yapmaz
    python client.py analyze mail.eml     # yerel .eml dosyasını analiz eder

Ortam değişkenleri:
    SPAMMAILD_API_URL   (varsayılan http://127.0.0.1:8100)
    API_KEY             sunucu X-API-Key istiyorsa
    EMAIL_ACCOUNT, EMAIL_APP_PASSWORD   Gmail uygulama şifresi (parola ile giriş kapalı)
    IMAP_SERVER         (varsayılan imap.gmail.com)
"""

from __future__ import annotations

import argparse
import imaplib
import os
import sys
from pathlib import Path

import httpx

DEFAULT_API_URL = "http://127.0.0.1:8100"
BAND_LABELS = {"clean": "TEMİZ", "suspicious": "ŞÜPHELİ", "spam": "SPAM / PHISHING"}


class ClientError(RuntimeError):
    """Kullanıcıya gösterilecek istemci hatası."""


def analyze_raw(raw: bytes, api_url: str, api_key: str | None, timeout: float = 30.0) -> dict:
    headers = {"Content-Type": "message/rfc822"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        response = httpx.post(
            f"{api_url.rstrip('/')}/v1/analyze", content=raw, headers=headers, timeout=timeout
        )
    except httpx.HTTPError as exc:
        raise ClientError(f"API'ye ulaşılamadı: {exc}") from exc
    if response.status_code != 200:
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = response.text[:200]
        raise ClientError(f"API {response.status_code} döndü: {message}")
    return response.json()


def fetch_unseen(limit: int) -> list[bytes]:
    """Okunmamış son `limit` maili `BODY.PEEK[]` ile çeker; okundu bayrağı değişmez."""
    account = os.environ.get("EMAIL_ACCOUNT")
    password = os.environ.get("EMAIL_APP_PASSWORD")
    if not account or not password:
        raise ClientError("EMAIL_ACCOUNT ve EMAIL_APP_PASSWORD tanımlı olmalı.")
    server = os.environ.get("IMAP_SERVER", "imap.gmail.com")
    messages: list[bytes] = []
    with imaplib.IMAP4_SSL(server) as mail:
        mail.login(account, password)
        mail.select("INBOX", readonly=True)
        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            raise ClientError("IMAP araması başarısız.")
        ids = data[0].split()[-limit:]
        for message_id in ids:
            status, parts = mail.fetch(message_id, "(BODY.PEEK[])")
            if status != "OK":
                continue
            for part in parts:
                if isinstance(part, tuple):
                    messages.append(part[1])
    return messages


def print_result(result: dict) -> None:
    message = result["message"]
    print("=" * 60)
    print(f"Gönderen : {message['sender'] or 'bilinmiyor'}")
    print(f"Konu     : {message['subject'] or 'konu yok'}")
    print(f"Risk     : {result['risk']}/100  {BAND_LABELS.get(result['band'], result['band'])}")
    auth = result["auth"]
    print(
        f"Kimlik   : SPF {auth['spf']['result']}, DKIM {auth['dkim']['result']}, "
        f"DMARC {auth['dmarc']['result']}"
    )
    print("Nedenler :")
    for reason in result["reasons"]:
        print(f"  {reason['impact']:+.1f}  [{reason['source']}] {reason['text']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SpamMailD istemcisi")
    parser.add_argument("--api-url", default=os.environ.get("SPAMMAILD_API_URL", DEFAULT_API_URL))
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="IMAP'ten okunmamış mailleri analiz et")
    fetch.add_argument("--limit", type=int, default=1)
    analyze = sub.add_parser("analyze", help=".eml dosyasını analiz et")
    analyze.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    api_key = os.environ.get("API_KEY")

    try:
        if args.command == "analyze":
            raws = [args.path.read_bytes()]
        else:
            raws = fetch_unseen(max(args.limit, 1))
            if not raws:
                print("Okunmamış mail yok.")
                return 0
        for raw in raws:
            print_result(analyze_raw(raw, args.api_url, api_key))
    except (ClientError, OSError, imaplib.IMAP4.error) as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
