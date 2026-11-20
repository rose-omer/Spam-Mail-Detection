import asyncio
import io
import struct
import zipfile

import pytest

from spammaild.analyzers.attachments import analyze_attachments, detect_type, inspect_attachment
from spammaild.clients import scanners
from spammaild.clients.http import ScanStatus
from spammaild.clients.scanners import ClamdScanner, ScanResult, parse_clamd_reply
from spammaild.parsing import Attachment
from tests.conftest import EICAR

MB = 1024 * 1024


def _zip(entries: dict[str, bytes], encrypted: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    data = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile şifreli yazamaz; "şifreli" bitini yerel ve merkezi başlıkta elle aç.
        for signature, offset in ((b"PK", 6), (b"PK", 8)):
            position = data.find(signature)
            data[position + offset] |= 0x1
    return bytes(data)


class FakeScanner:
    """EICAR dizesini "infected" sayan sahte tarayıcı."""

    def __init__(self, name="ClamAV", fail=False):
        self.name = name
        self.fail = fail

    async def scan(self, data: bytes) -> ScanResult:
        if self.fail:
            return ScanResult(ScanStatus.ERROR, "clamd erişilemedi")
        if EICAR in data:
            return ScanResult(ScanStatus.INFECTED, "Eicar-Test-Signature")
        return ScanResult(ScanStatus.CLEAN)


def _run(attachments, scanner_list):
    return asyncio.run(analyze_attachments(attachments, scanner_list, 25 * MB, 50 * MB))


def test_double_extension_from_fixture(parsed_fixture):
    finding = inspect_attachment(parsed_fixture("double_extension.eml").attachments[0])
    assert {"double_extension", "executable"} <= set(finding.flags)


@pytest.mark.parametrize(
    ("data", "kind"),
    [(b"MZ\x90\x00", "exe"), (b"%PDF-1.7", "pdf"), (b"\x89PNG\r\n", "png"), (b"merhaba", "text")],
)
def test_magic_type(data, kind):
    assert detect_type(data) == kind


def test_pdf_named_executable_content_is_flagged():
    finding = inspect_attachment(Attachment("belge.pdf", "application/pdf", b"MZ\x90\x00rest"))
    assert finding.detected_type == "exe"
    assert "executable" in finding.flags


def test_macro_office_document():
    data = _zip({"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"vba"})
    finding = inspect_attachment(Attachment("rapor.docx", "application/octet-stream", data))
    assert finding.detected_type == "office"
    assert "macro" in finding.flags


def test_encrypted_archive():
    data = _zip({"gizli.txt": b"x"}, encrypted=True)
    finding = inspect_attachment(Attachment("arsiv.zip", "application/zip", data))
    assert "encrypted_archive" in finding.flags


def test_eicar_is_infected_with_fake_scanner():
    signals, findings = _run(
        [Attachment("test.com", "application/octet-stream", EICAR)], [FakeScanner()]
    )
    assert findings[0].scans["ClamAV"].status == ScanStatus.INFECTED
    assert "attachment_infected" in {signal.name for signal in signals}


def test_scanner_error_is_not_clean():
    signals, findings = _run(
        [Attachment("a.txt", "text/plain", b"merhaba")], [FakeScanner(fail=True)]
    )
    assert findings[0].scans["ClamAV"].status == ScanStatus.ERROR
    scan_signals = [signal for signal in signals if signal.name == "attachment_scan_unknown"]
    assert scan_signals and scan_signals[0].status == "error"


def test_size_limits_skip_scan():
    big = Attachment("buyuk.bin", "application/octet-stream", b"\0" * (2 * MB))
    signals, findings = asyncio.run(analyze_attachments([big], [FakeScanner()], MB, 50 * MB))
    assert "too_large" in findings[0].flags
    assert findings[0].scans == {}
    assert "attachment_too_large" in {signal.name for signal in signals}


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        ("stream: OK", ScanStatus.CLEAN),
        ("stream: Eicar-Test-Signature FOUND", ScanStatus.INFECTED),
        ("INSTREAM size limit exceeded. ERROR", ScanStatus.ERROR),
        ("", ScanStatus.ERROR),
    ],
)
def test_parse_clamd_reply(reply, status):
    assert parse_clamd_reply(reply).status == status


class _FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class _FakeReader:
    def __init__(self, reply: bytes):
        self.reply = reply

    async def readuntil(self, separator):
        return self.reply


def test_clamd_instream_framing(monkeypatch):
    writer = _FakeWriter()

    async def fake_open_connection(host, port):
        assert (host, port) == ("clamav", 3310)
        return _FakeReader(b"stream: Eicar-Test-Signature FOUND\0"), writer

    monkeypatch.setattr(scanners.asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(ClamdScanner("clamav", 3310).scan(EICAR))
    assert result.status == ScanStatus.INFECTED
    assert result.detail == "Eicar-Test-Signature"
    sent = bytes(writer.buffer)
    assert sent.startswith(b"zINSTREAM\0")
    assert sent[10:14] == struct.pack("!L", len(EICAR))
    assert sent.endswith(struct.pack("!L", 0))
    assert writer.closed


def test_clamd_unreachable_is_error(monkeypatch):
    async def refuse(host, port):
        raise ConnectionRefusedError

    monkeypatch.setattr(scanners.asyncio, "open_connection", refuse)
    result = asyncio.run(ClamdScanner("clamav").scan(b"x"))
    assert result.status == ScanStatus.ERROR
