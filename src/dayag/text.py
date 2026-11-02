"""Helpers for handling untrusted text from emails."""

from __future__ import annotations

import re

# Zero-width characters attackers insert to split words ("pass<ZWSP>word")
# so keyword filters miss them.
_INVISIBLE = frozenset(chr(c) for c in (0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
# Bidirectional controls, including RIGHT-TO-LEFT OVERRIDE (U+202E), which
# reorder how text is displayed.
_BIDI = frozenset(chr(c) for c in (0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)))
# C0/C1 control characters except tab and newline. Printing them to a terminal
# could inject escape sequences.
_CONTROL = re.compile(
    "["
    + "".join(
        re.escape(chr(c)) for c in (*range(0x00, 0x09), *range(0x0B, 0x20), *range(0x7F, 0xA0))
    )
    + "]"
)
_SPACE = re.compile(r"\s+")
_HEBREW = re.compile(f"[{chr(0x0590)}-{chr(0x05FF)}]")


def contains_hebrew(text: str) -> bool:
    return bool(_HEBREW.search(text))


def has_bidi_controls(text: str) -> bool:
    return any(c in _BIDI for c in text)


def for_display(text: str, limit: int | None = None) -> str:
    """Make untrusted text safe to show: bidi controls become visible markers,
    control characters are removed."""
    text = "".join(f"[U+{ord(c):04X}]" if c in _BIDI else c for c in text)
    text = _CONTROL.sub("", text)
    if limit is not None and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def for_matching(text: str) -> str:
    """Normalise text for phrase matching: drop invisible characters, collapse whitespace."""
    text = "".join(c for c in text if c not in _INVISIBLE and c not in _BIDI)
    return _SPACE.sub(" ", text).strip()
