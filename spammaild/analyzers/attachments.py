"""Ek analizi: tür tespiti (sihirli baytlar), uzantı denetimi ve dosya taraması."""

from __future__ import annotations

import asyncio
import hashlib
import io
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from spammaild.clients.http import ScanStatus
from spammaild.clients.scanners import FileScanner, ScanResult
from spammaild.parsing import Attachment
from spammaild.scoring import Signal, Source, make_signal

EXECUTABLE_EXT = frozenset(
    "exe scr com bat cmd pif js jse vbs vbe wsf jar msi ps1 lnk hta cpl dll iso img".split()
)
MACRO_EXT = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm"})
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "exe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
)


@dataclass(slots=True)
class AttachmentFinding:
    filename: str
    content_type: str
    detected_type: str
    size: int
    sha256: str
    flags: list[str] = field(default_factory=list)
    scans: dict[str, ScanResult] = field(default_factory=dict)


def detect_type(data: bytes) -> str:
    for magic, kind in _SIGNATURES:
        if data.startswith(magic):
            return kind
    return "text" if data[:512].isascii() else "binary"


def _zip_flags(data: bytes) -> tuple[str, list[str]]:
    flags: list[str] = []
    kind = "zip"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError):
        return kind, flags
    names = [info.filename for info in infos]
    if "[Content_Types].xml" in names:
        kind = "office"
    if any(name.endswith("vbaProject.bin") for name in names):
        flags.append("macro")
    if any(info.flag_bits & 0x1 for info in infos):
        flags.append("encrypted_archive")
    return kind, flags


def inspect_attachment(attachment: Attachment) -> AttachmentFinding:
    data = attachment.data
    detected = detect_type(data)
    flags: list[str] = []
    if detected == "zip":
        detected, zip_flags = _zip_flags(data)
        flags.extend(zip_flags)
    elif detected == "ole" and (b"_VBA_PROJECT" in data or b"VBA" in data):
        flags.append("macro")

    suffixes = [s.lstrip(".").lower() for s in PurePosixPath(attachment.filename).suffixes]
    last_ext = suffixes[-1] if suffixes else ""
    if last_ext in MACRO_EXT and "macro" not in flags:
        flags.append("macro")
    if len(suffixes) >= 2 and last_ext in EXECUTABLE_EXT:
        flags.append("double_extension")
    if last_ext in EXECUTABLE_EXT or detected in {"exe", "elf"}:
        flags.append("executable")

    return AttachmentFinding(
        filename=attachment.filename,
        content_type=attachment.content_type,
        detected_type=detected,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        flags=flags,
    )


_FLAG_SIGNALS = {
    "double_extension": (
        "attachment_double_extension",
        2.0,
        "{name} çift uzantılı; gerçek tür gizleniyor.",
    ),
    "executable": ("attachment_executable", 2.0, "{name} çalıştırılabilir dosya."),
    "macro": ("attachment_macro", 1.5, "{name} makro içeren Office belgesi."),
    "encrypted_archive": (
        "attachment_encrypted_archive",
        1.5,
        "{name} parola korumalı arşiv; içerik taranamıyor.",
    ),
    "too_large": ("attachment_too_large", 1.0, "{name} boyut sınırını aşıyor; taranmadı."),
}


async def _scan(finding: AttachmentFinding, data: bytes, scanners: list[FileScanner]) -> None:
    results = await asyncio.gather(*(scanner.scan(data) for scanner in scanners))
    finding.scans = {
        scanner.name: result for scanner, result in zip(scanners, results, strict=True)
    }


async def analyze_attachments(
    attachments: list[Attachment],
    scanners: list[FileScanner],
    max_bytes: int,
    max_total_bytes: int,
) -> tuple[list[Signal], list[AttachmentFinding]]:
    findings: list[AttachmentFinding] = []
    jobs = []
    total = 0
    for attachment in attachments:
        finding = inspect_attachment(attachment)
        findings.append(finding)
        total += finding.size
        if finding.size > max_bytes or total > max_total_bytes:
            finding.flags.append("too_large")
            continue
        if scanners:
            jobs.append(_scan(finding, attachment.data, scanners))
    await asyncio.gather(*jobs)

    signals: list[Signal] = []
    for finding in findings:
        for flag in finding.flags:
            name, score, template = _FLAG_SIGNALS[flag]
            signals.append(
                make_signal(name, score, template.format(name=finding.filename), Source.ATTACHMENT)
            )
        for scanner_name, result in finding.scans.items():
            if result.status == ScanStatus.INFECTED:
                detail = f" ({result.detail})" if result.detail else ""
                signals.append(
                    make_signal(
                        "attachment_infected",
                        3.0,
                        f"{scanner_name} {finding.filename} dosyasını zararlı buldu{detail}.",
                        Source.ATTACHMENT,
                    )
                )
            elif result.status in {ScanStatus.ERROR, ScanStatus.UNKNOWN}:
                label = "hata verdi" if result.status == ScanStatus.ERROR else "sonuç vermedi"
                signals.append(
                    make_signal(
                        "attachment_scan_unknown",
                        1.0,
                        f"{scanner_name} {finding.filename} için {label}; dosya temiz sayılmadı.",
                        Source.ATTACHMENT,
                        status=str(result.status),
                    )
                )
    return signals, findings
