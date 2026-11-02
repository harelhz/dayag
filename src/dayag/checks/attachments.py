"""Judge attachments from the facts gathered by filetypes.inspect_attachment."""

from __future__ import annotations

import re

from ..context import Context
from ..filetypes import extensions
from ..knowledge import (
    ARCHIVE_EXTENSIONS,
    DECOY_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_KINDS,
    EXPECTED_KINDS,
    HTML_EXTENSIONS,
    MACRO_EXTENSIONS,
    ONENOTE_EXTENSIONS,
)
from ..model import AttachmentInfo, Finding, hit
from ..text import for_display, has_bidi_controls

_KIND_NAMES = {
    "pe": "a Windows executable", "elf": "a Linux executable", "macho": "a macOS executable",
    "lnk": "a Windows shortcut", "script": "a script", "pdf": "a PDF", "zip": "a ZIP archive",
    "ooxml": "an Office document", "ole": "a legacy Office file", "html": "an HTML page",
    "svg": "an SVG image", "rtf": "an RTF document", "iso": "a disk image", "vhd": "a disk image",
    "onenote": "a OneNote file", "rar": "a RAR archive", "7z": "a 7-Zip archive",
    "gzip": "a gzip archive", "png": "a PNG image", "jpeg": "a JPEG image", "gif": "a GIF image",
    "text": "plain text", "jar": "a Java archive",
}  # fmt: skip
_RISKY_FINAL = EXECUTABLE_EXTENSIONS | DISK_IMAGE_EXTENSIONS | HTML_EXTENSIONS
_PADDED = re.compile(r"\s{3,}\.[\w-]+$")
_ACTIVE_PDF = ("JavaScript", "launch action", "embedded file", "rich media")


def _is_disguised(name: str) -> bool:
    exts = extensions(name)
    return (len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS and exts[-1] in _RISKY_FINAL) or bool(
        _PADDED.search(name)
    )


def _judge(a: AttachmentInfo) -> list[Finding]:
    findings: list[Finding] = []
    name = for_display(a.filename)
    exts = extensions(a.filename)
    last = exts[-1] if exts else ""
    evidence = [f"sha256:{a.sha256}"]

    def flag(rule_id: str, detail: str, label: str) -> None:
        findings.append(hit(rule_id, detail, evidence))
        if label not in a.flags:
            a.flags.append(label)

    if has_bidi_controls(a.filename):
        flag("ATT-RTLO", f"'{name}' contains a text-direction control character.", "RTLO")
    if _is_disguised(a.filename):
        flag("ATT-DOUBLE-EXT", f"'{name}' hides its real extension (.{last}).", "double extension")
    if last in EXECUTABLE_EXTENSIONS or a.kind in EXECUTABLE_KINDS:
        what = _KIND_NAMES.get(a.kind, "code") if a.kind in EXECUTABLE_KINDS else f"a .{last} file"
        flag("ATT-EXECUTABLE", f"'{name}' is {what}.", "executable")

    expected = EXPECTED_KINDS.get(last)
    if expected and a.kind not in expected and a.kind != "unknown":
        flag(
            "ATT-TYPE-MISMATCH",
            f"'{name}' is named .{last} but is actually {_KIND_NAMES.get(a.kind, a.kind)}.",
            f"really {a.kind}",
        )

    if last in DISK_IMAGE_EXTENSIONS or a.kind in ("iso", "vhd"):
        flag("ATT-DISK-IMAGE", f"'{name}' is a disk image.", "disk image")

    if last in HTML_EXTENSIONS or a.kind in ("html", "svg"):
        traits = [t for t in a.html_traits if t != "smuggling"]
        extra = f" It contains: {', '.join(traits)}." if traits else ""
        flag("ATT-HTML", f"'{name}' is a local web page.{extra}", "HTML")
        if "smuggling" in a.html_traits:
            flag(
                "ATT-HTML-SMUGGLING",
                f"'{name}' assembles a file from embedded data and triggers a download.",
                "HTML smuggling",
            )

    if a.archive_encrypted:
        flag("ATT-ENCRYPTED-ARCHIVE", f"'{name}' is password-protected.", "encrypted")
    risky_members = [
        m
        for m in a.archive_members
        if (extensions(m) or [""])[-1] in _RISKY_FINAL | ONENOTE_EXTENSIONS
        or _is_disguised(m)
        or has_bidi_controls(m)
    ]
    if risky_members:
        flag(
            "ATT-ARCHIVE-RISKY",
            f"'{name}' contains {', '.join(for_display(m) for m in risky_members[:5])}.",
            "risky content",
        )
    nested = [m for m in a.archive_members if (extensions(m) or [""])[-1] in ARCHIVE_EXTENSIONS]
    if nested and "nested archive" not in a.flags:
        a.flags.append("nested archive")

    if a.macros or last in MACRO_EXTENSIONS:
        flag(
            "ATT-MACRO",
            f"'{name}' contains VBA macros."
            if a.macros
            else f"'{name}' is a macro-enabled Office format.",
            "macros",
        )
    if a.remote_content:
        flag("ATT-REMOTE-TEMPLATE", f"'{name}' loads {a.remote_content}.", "remote content")
    if last in ONENOTE_EXTENSIONS or a.kind == "onenote":
        flag("ATT-ONENOTE", f"'{name}' is a OneNote file.", "OneNote")
    active = [t for t in a.pdf_traits if t in _ACTIVE_PDF]
    if active:
        flag("ATT-PDF-ACTIVE", f"'{name}' contains {', '.join(a.pdf_traits)}.", "active PDF")
    return findings


def check_attachments(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in ctx.attachments:
        findings += _judge(attachment)
    return findings
