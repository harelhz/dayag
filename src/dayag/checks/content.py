"""Judge what the email says and how its HTML is built."""

from __future__ import annotations

import re

from ..context import Context
from ..knowledge import PHRASES
from ..model import Finding, hit
from ..text import contains_hebrew


def _compile(phrases: tuple[str, ...]) -> re.Pattern[str]:
    patterns = [
        re.escape(p) if contains_hebrew(p) else r"\b" + re.escape(p) + r"\b" for p in phrases
    ]
    # Longest first so "gift cards" wins over "gift card".
    return re.compile("|".join(sorted(patterns, key=len, reverse=True)), re.IGNORECASE)


_PATTERNS = {rule_id: _compile(phrases) for rule_id, phrases in PHRASES.items()}
_DETAILS = {
    "CONTENT-GIFT-CARD": "The email asks for gift cards.",
    "CONTENT-PAYMENT": "The email asks for a payment, transfer or bank details.",
    "CONTENT-CREDENTIALS": "The email asks the reader to sign in or verify an account.",
    "CONTENT-URGENCY": "The email pressures the reader to act fast.",
    "CONTENT-GENERIC-GREETING": "The email does not address the reader by name.",
}
_REPLY_PREFIX = re.compile(r"^\s*(?:re|fw|fwd|aw|wg|tr|השב|העבר|הועבר)\s*:", re.IGNORECASE)
MIN_VISIBLE_TEXT = 60
MIN_HIDDEN_TEXT = 200


def check_content(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern in _PATTERNS.items():
        matches: list[str] = []
        for match in pattern.finditer(ctx.text):
            phrase = match.group(0).lower()
            if phrase not in matches:
                matches.append(phrase)
            if len(matches) >= 5:
                break
        if matches:
            findings.append(hit(rule_id, _DETAILS[rule_id], [f'"{m}"' for m in matches]))

    subject = ctx.email.header("Subject")
    threaded = ctx.email.header("In-Reply-To") or ctx.email.header("References")
    if _REPLY_PREFIX.match(subject) and not threaded:
        findings.append(
            hit(
                "CONTENT-FAKE-REPLY",
                "The subject looks like a reply or forward, but the email has no "
                "In-Reply-To or References header.",
                [subject],
            )
        )

    html = ctx.html
    if html.password_fields:
        findings.append(hit("CONTENT-PASSWORD-FIELD", "The email body contains a password field."))
    if html.forms:
        findings.append(
            hit(
                "CONTENT-FORM",
                f"The email body contains {len(html.forms)} form(s).",
                [a for a in html.forms if a][:5],
            )
        )
    if html.scripts:
        findings.append(hit("CONTENT-SCRIPT", f"The email body contains {html.scripts} script(s)."))
    if html.hidden_chars >= MIN_HIDDEN_TEXT:
        findings.append(
            hit("CONTENT-HIDDEN-TEXT", f"{html.hidden_chars} characters of text are hidden.")
        )

    visible = max([len(html.text), *(len(t.strip()) for t in ctx.email.text_bodies)], default=0)
    images = [src for src, pixel in html.images if not pixel]
    image_files = [a for a in ctx.attachments if a.kind in ("png", "jpeg", "gif")]
    if visible < MIN_VISIBLE_TEXT and (images or image_files):
        findings.append(
            hit(
                "CONTENT-IMAGE-ONLY",
                f"Only {visible} characters of text next to {len(images) + len(image_files)} "
                "image(s). Check the images for QR codes.",
            )
        )
    pixels = [src for src, pixel in html.images if pixel]
    if pixels:
        findings.append(
            hit("CONTENT-TRACKING-PIXEL", f"{len(pixels)} tracking pixel(s).", pixels[:3])
        )
    return findings
