"""Inspect attachments statically: real file type, archive contents, active content.

Nothing is ever executed or extracted to disk. Archives are listed from their
central directory, and decompression is bounded so a zip or PDF bomb cannot
exhaust memory.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
import zlib
from collections.abc import Iterator

from .htmlscan import HtmlScan
from .model import AttachmentInfo
from .parsing import RawAttachment
from .urls import find_urls

MAX_ARCHIVE_MEMBERS = 1000
MAX_INNER_READ = 1_000_000
MAX_PDF_STREAMS = 200
MAX_INFLATED = 5_000_000

_ONENOTE = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")
_OLE = bytes.fromhex("D0CF11E0A1B11AE1")
_LNK = bytes.fromhex("4C0000000114020000000000C000000000000046")
_VBA_PROJECT_UTF16 = "_VBA_PROJECT".encode("utf-16-le")


def sniff(data: bytes) -> str:
    """Identify a file by its content, ignoring its name."""
    head = data[:2048]
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "macho"
    if head.startswith(_LNK):
        return "lnk"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(_OLE):
        return "ole"
    if head.startswith(_ONENOTE):
        return "onenote"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"vhdxfile") or data[-512:].startswith(b"conectix"):
        return "vhd"
    if any(data[offset : offset + 5] == b"CD001" for offset in (0x8001, 0x8801, 0x9001)):
        return "iso"
    if head.startswith(b"#!"):
        return "script"
    if b"\x00" not in head:
        text = (
            head.decode("utf-8", errors="ignore")
            .lstrip("\N{ZERO WIDTH NO-BREAK SPACE} \t\r\n")
            .lower()
        )
        if text.startswith("<svg") or ("<svg" in text and text.startswith("<?xml")):
            return "svg"
        if re.match(r"<(!doctype html|html|head|body|script|meta|form|div|iframe)\b", text):
            return "html"
        return "text"
    return "unknown"


def extensions(filename: str) -> list[str]:
    """All extensions, lower case: 'Invoice.PDF .exe' -> ['pdf', 'exe']."""
    name = filename.strip().rstrip(".").lower()
    parts = name.split(".")
    return [p.strip() for p in parts[1:] if p.strip()]


def inspect_attachment(raw: RawAttachment) -> AttachmentInfo:
    data = raw.payload
    info = AttachmentInfo(
        filename=raw.filename,
        content_type=raw.content_type,
        size=len(data),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        kind=sniff(data),
        inline=raw.inline,
    )
    if info.kind == "zip":
        _inspect_zip(data, info)
    elif info.kind == "ole":
        info.macros = _VBA_PROJECT_UTF16 in data or b"_VBA_PROJECT" in data
    elif info.kind == "pdf":
        _inspect_pdf(data, info)
    elif info.kind in ("html", "svg") or (
        info.kind == "text" and (extensions(raw.filename) or [""])[-1] in ("html", "htm", "svg")
    ):
        _inspect_html(data, info)
    return info


_EXTERNAL_REL = re.compile(
    r"<Relationship\b[^>]*\bType=\"[^\"]*/(attachedTemplate|oleObject|frame|subDocument)\""
    r"[^>]*>",
    re.IGNORECASE,
)


def _inspect_zip(data: bytes, info: AttachmentInfo) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return
    with archive:
        members = archive.infolist()[:MAX_ARCHIVE_MEMBERS]
        names = [m.filename for m in members]
        info.archive_encrypted = any(m.flag_bits & 0x1 for m in members)
        if "[Content_Types].xml" in names:
            info.kind = "ooxml"
            info.macros = any(n.lower().endswith("vbaproject.bin") for n in names)
            for member in members:
                if not member.filename.endswith(".rels") or member.flag_bits & 0x1:
                    continue
                try:
                    with archive.open(member) as handle:
                        rels = handle.read(MAX_INNER_READ).decode("utf-8", "replace")
                except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
                    continue
                for match in _EXTERNAL_REL.finditer(rels):
                    tag = match.group(0)
                    target = re.search(r'Target="([^"]+)"', tag)
                    if 'TargetMode="External"' in tag and target:
                        info.remote_content = f"{match.group(1)}: {target.group(1)}"
                        info.urls.append(target.group(1))
                        break
        elif "META-INF/MANIFEST.MF" in names:
            info.kind = "jar"
        else:
            info.archive_members = names


_PDF_KEYS = {
    "JavaScript": r"/(?:JavaScript|JS)(?![A-Za-z])",
    "launch action": r"/Launch(?![A-Za-z])",
    "embedded file": r"/EmbeddedFiles?(?![A-Za-z])",
    "rich media": r"/RichMedia(?![A-Za-z])",
    "opens with an action": r"/OpenAction(?![A-Za-z])",
    "form submission": r"/SubmitForm(?![A-Za-z])",
    "XFA form": r"/XFA(?![A-Za-z])",
}
_PDF_URI = re.compile(r"/URI\s*\(((?:\\.|[^\\)]){1,2048})\)")
_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)


def _inflated_streams(data: bytes) -> Iterator[bytes]:
    for index, match in enumerate(_STREAM.finditer(data)):
        if index >= MAX_PDF_STREAMS:
            return
        try:
            yield zlib.decompressobj().decompress(match.group(1), MAX_INFLATED)
        except zlib.error:
            continue


def _inspect_pdf(data: bytes, info: AttachmentInfo) -> None:
    traits: list[str] = []
    for chunk in [data, *_inflated_streams(data)]:
        text = chunk.decode("latin-1")
        for trait, pattern in _PDF_KEYS.items():
            if trait not in traits and re.search(pattern, text):
                traits.append(trait)
        for uri in _PDF_URI.findall(text):
            uri = re.sub(r"\\(.)", r"\1", uri)
            if uri not in info.urls:
                info.urls.append(uri)
    info.pdf_traits = traits


_SMUGGLING_BUILD = re.compile(r"new\s+blob\s*\(|createobjecturl|mssaveoropenblob|mssaveblob")
_SMUGGLING_DATA = re.compile(r"atob\s*\(|uint8array|base64|fromcharcode")


def _inspect_html(data: bytes, info: AttachmentInfo) -> None:
    text = data[:5_000_000].decode("utf-8", errors="replace")
    lowered = text.lower()
    scan = HtmlScan().scan(text)
    traits = []
    if scan.forms or "<form" in lowered:
        traits.append("form")
    if scan.password_fields or re.search(r"type\s*=\s*['\"]?password", lowered):
        traits.append("password field")
    if _SMUGGLING_BUILD.search(lowered) and _SMUGGLING_DATA.search(lowered):
        traits.append("smuggling")
    if scan.scripts or "<script" in lowered:
        traits.append("script")
    if re.search(r"window\.location|location\.(?:href|replace)|http-equiv=['\"]?refresh", lowered):
        traits.append("redirect")
    if re.search(r"\beval\s*\(|unescape\s*\(|document\.write\s*\(", lowered):
        traits.append("obfuscation")
    info.html_traits = traits
    for url in [*scan.forms, *(href for href, _ in scan.anchors), *find_urls(text)]:
        if url and re.match(r"(?i)https?://", url) and url not in info.urls:
            info.urls.append(url)
