"""Malformed input must degrade, never crash: phishing emails are often broken on purpose."""

from __future__ import annotations

import dataclasses
import io
import json
import random

import pytest
from conftest import build_email, run
from rich.console import Console

from dayag.demo import SAMPLES
from dayag.iocs import iocs_to_csv, iocs_to_json, iocs_to_stix
from dayag.model import Ioc, Report
from dayag.render.html import render_html
from dayag.render.terminal import render_terminal

HEADERS = b"From: a@b.example\r\nTo: c@d.example\r\n"


def render_everything(report: Report) -> None:
    """Every output, encoded as UTF-8 the way it is written to a file or a response."""
    console = io.StringIO()
    render_terminal(report, Console(file=console, width=120), verbose=True)
    outputs = [
        console.getvalue(),
        render_html(report),
        iocs_to_csv(report),
        iocs_to_json(report),
        iocs_to_stix(report),
        json.dumps(report.to_dict(), ensure_ascii=False, default=str),
    ]
    for output in outputs:
        output.encode("utf-8")


@pytest.mark.parametrize(
    "raw",
    [
        # CharsetError: a raw byte inside the charset name of an encoded word
        HEADERS + b"Subject: =?utf\xa5-8?b?SGVsbG8=?=\r\n\r\nhi\r\n",
        # HeaderParseError: a control byte inside a base64 encoded word
        HEADERS
        + b"Subject: =?utf-8?b?15TXl9eR15nXnNeUINep15zXmiDXntee16rXmdeg15QgL\x08DXoNeT16jXqSDX"
        b"qtep15zXldedINeT?=\r\n\r\nhi\r\n",
        # UnicodeEncodeError re-serialising an attached message with a raw byte in a header
        b"Content-Type: message/rfc822\r\n\r\nMIME-Version: \xa51.0\r\n",
        # ... or in a body that looks like an encoded word
        b"Content-Type: message/rfc822\r\n\r\nContent-Type: multipart/mixed; boundary=b\r\n"
        b"<p>=?utf\xa5-8?b?x</p>\r\n",
        # ValueError: a NUL in the body's charset name
        HEADERS + b'Subject: x\r\nContent-Type: text/plain; charset="utf\x00-8"\r\n\r\nhi\r\n',
        # Raw 8-bit bytes in addresses end up in the IOCs and the STIX ids
        b"From: PayPal <service@paypal.com\xfa\r\nTo: c@d.example\r\nSubject: hi\r\n\r\n"
        b"https://evil.example/\xe9\r\n",
    ],
    ids=["charset", "header-parse", "rfc822-header", "rfc822-body", "nul-charset", "8bit-ioc"],
)
def test_malformed_input_does_not_crash(raw: bytes) -> None:
    render_everything(run(raw))


def test_bad_charset_keeps_the_raw_subject() -> None:
    report = run(HEADERS + b"Subject: =?utf\xa5-8?b?SGVsbG8=?=\r\n\r\nhi\r\n")
    assert report.summary.subject == "=?utf�-8?b?SGVsbG8=?="


def test_raw_utf8_headers_are_decoded() -> None:
    raw = HEADERS + "Subject: החבילה שלך ממתינה".encode() + b"\r\n\r\nhi\r\n"
    assert run(raw).summary.subject == "החבילה שלך ממתינה"


def test_stix_export_tolerates_surrogates() -> None:
    report = run(build_email())
    report = dataclasses.replace(report, iocs=[Ioc("email", "a\udce9@b.example", "From", True)])
    bundle = json.loads(iocs_to_stix(report))
    assert bundle["objects"][0]["id"].startswith("indicator--")


# Bytes that break header decoding and re-serialisation.
_TOKENS = [b"=?utf\xa5-8?b?", b"\xa5", b"\xff", b"\x00", b"\x08", b"=?", b"?=", b"?b?", b"?q?",
           b"\r\n", b";", b"<", b">", b'"']  # fmt: skip


def _mutate(rng: random.Random, data: bytes) -> bytes:
    out = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.random()
        at = rng.randrange(len(out) + 1)
        if op < 0.35 and out:
            out[min(at, len(out) - 1)] = rng.randrange(256)
        elif op < 0.7:
            out[at:at] = rng.choice(_TOKENS)
        elif op < 0.85:
            del out[at : at + rng.randint(1, 40)]
        else:
            out[at:at] = out[max(0, at - 60) : at]
    return bytes(out)


@pytest.mark.parametrize("sample", [s.name for s in SAMPLES])
def test_mutated_samples_never_crash(sample: str, sample_bytes) -> None:
    original = sample_bytes(sample)
    rng = random.Random(sample)  # deterministic, so a failure reproduces
    for _ in range(60):
        raw = _mutate(rng, original)
        try:
            render_everything(run(raw))
        except Exception as error:  # pragma: no cover - only on failure
            raise AssertionError(f"crash on mutated {sample}: {raw!r}") from error
