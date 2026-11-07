"""Turn raw RFC 5322 bytes into headers, bodies and attachments.

Headers are read with raw_items() and decoded by hand rather than through
the email package's structured header parser, which can raise on the
malformed headers phishing emails are full of.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from email import policy
from email.errors import MessageError
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses

from .model import Address

MAX_EMAIL_BYTES = 25 * 1024 * 1024


class EmailTooLarge(ValueError):
    pass


@dataclass
class RawAttachment:
    filename: str
    content_type: str
    payload: bytes
    inline: bool = False


@dataclass
class ParsedEmail:
    message: Message
    size: int
    text_bodies: list[str] = field(default_factory=list)
    html_bodies: list[str] = field(default_factory=list)
    attachments: list[RawAttachment] = field(default_factory=list)

    def headers(self, name: str) -> list[str]:
        return header_values(self.message, name)

    def header(self, name: str) -> str:
        values = self.headers(name)
        return values[0] if values else ""

    def addresses(self, name: str) -> list[Address]:
        return parse_addresses(self.message, name)


def load_message(raw: bytes) -> Message:
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailTooLarge(f"email is larger than {MAX_EMAIL_BYTES // (1024 * 1024)} MB")
    return BytesParser(policy=policy.default).parsebytes(raw)


def _clean(text: str) -> str:
    """Decode raw 8-bit bytes, which the parser leaves as surrogate escapes, as UTF-8.

    A string with surrogates cannot be encoded, so it would crash whatever
    writes it out: a report, an export or a hash.
    """
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:  # a surrogate that is not an escaped byte
        return text.encode("utf-8", "replace").decode("utf-8")


def _decode_words(value: str) -> str:
    """Decode RFC 2047 encoded words (=?utf-8?b?...?=), tolerating bad input."""
    value = _clean(value)
    try:
        return _clean(str(make_header(decode_header(value))))
    except (LookupError, UnicodeError, ValueError, TypeError, MessageError):
        return value


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value).strip()


def header_values(message: Message, name: str) -> list[str]:
    """All values of a header, top to bottom, decoded and unfolded."""
    wanted = name.lower()
    return [
        _decode_words(_unfold(str(value)))
        for key, value in message.raw_items()
        if key.lower() == wanted
    ]


def parse_addresses(message: Message, name: str) -> list[Address]:
    """Parse address headers on the raw value, then decode display names.

    Decoding first would break on encoded names containing commas.
    """
    wanted = name.lower()
    raw_values = [_clean(_unfold(str(v))) for k, v in message.raw_items() if k.lower() == wanted]
    result = []
    for display, address in getaddresses(raw_values):
        if address or display:
            result.append(Address(_decode_words(display).strip(), address.strip()))
    return result


def find_reported_message(message: Message) -> Message | None:
    """The original email inside a 'report phishing' forward, if the message is one.

    Only unwraps when there is exactly one attached message, so phishing that
    nests emails to dodge scanners is still analysed as a whole.
    """
    attached = [p for p in _leaf_parts(message) if p.get_content_type() == "message/rfc822"]
    if len(attached) != 1:
        return None
    payload = attached[0].get_payload()
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        return payload[0]
    return None


def _leaf_parts(part: Message) -> Iterator[Message]:
    if part.get_content_type() == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                if isinstance(sub, Message):
                    yield from _leaf_parts(sub)
        return
    yield part


def _decode_text(part: Message) -> str:
    if isinstance(part, EmailMessage):
        try:
            content = part.get_content()
            if isinstance(content, str):
                return _clean(content)
        except (LookupError, UnicodeError, ValueError, AssertionError, KeyError, MessageError):
            pass
    payload = part.get_payload(decode=True)
    data = payload if isinstance(payload, bytes) else b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except (LookupError, ValueError):  # unknown charset, or one with a NUL in its name
        return data.decode("utf-8", errors="replace")


def _payload_bytes(part: Message) -> bytes:
    if part.get_content_type() == "message/rfc822":
        payload = part.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Message):
            # The parser keeps no copy of the original bytes, so the attached
            # message is serialised again, which fails on malformed headers.
            for flatten_policy in (payload[0].policy, policy.compat32):
                try:
                    return payload[0].as_bytes(policy=flatten_policy)
                except (LookupError, UnicodeError, ValueError, TypeError, MessageError):
                    continue
        return b""
    data = part.get_payload(decode=True)
    return data if isinstance(data, bytes) else b""


def extract(message: Message, size: int) -> ParsedEmail:
    """Split a message into text bodies, HTML bodies and attachments."""
    email = ParsedEmail(message=message, size=size)
    # A top-level message/rfc822 is the message itself, not an attachment.
    parts = list(_leaf_parts(message)) if message.is_multipart() else [message]
    for part in parts:
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if filename:
            filename = _decode_words(filename)
        is_body = (
            disposition != "attachment"
            and not filename
            and ctype
            in (
                "text/plain",
                "text/html",
            )
        )
        if is_body:
            text = _decode_text(part)
            (email.html_bodies if ctype == "text/html" else email.text_bodies).append(text)
            continue
        if ctype.startswith("multipart/"):
            continue
        default_name = "attached-message.eml" if ctype == "message/rfc822" else "(unnamed)"
        email.attachments.append(
            RawAttachment(
                filename=filename or default_name,
                content_type=ctype,
                payload=_payload_bytes(part),
                inline=disposition == "inline" or bool(part.get("Content-ID")),
            )
        )
    return email
