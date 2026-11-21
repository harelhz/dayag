from __future__ import annotations

from collections.abc import Iterable
from email.message import EmailMessage

import pytest

from dayag.analyzer import analyze
from dayag.demo import get_sample
from dayag.model import Report

DEFAULT_HEADERS = {
    "From": '"Alice Levi" <alice@contoso.com>',
    "To": "bob@contoso.com",
    "Subject": "Lunch on Thursday",
    "Date": "Mon, 02 Nov 2026 10:00:00 +0200",
    "Message-ID": "<test-1@contoso.com>",
}


def build_email(
    headers: dict[str, str | list[str]] | None = None,
    text: str | None = "See you there.",
    html: str | None = None,
    attachments: Iterable[tuple[str, bytes, str]] = (),
    drop: Iterable[str] = (),
) -> bytes:
    """Craft an email for a test. Header values given as lists are repeated."""
    merged: dict[str, str | list[str]] = {**DEFAULT_HEADERS, **(headers or {})}
    msg = EmailMessage()
    for name, value in merged.items():
        if name in drop:
            continue
        for item in value if isinstance(value, list) else [value]:
            msg[name] = item
    if text is not None:
        msg.set_content(text)
    if html is not None:
        if text is not None:
            msg.add_alternative(html, subtype="html")
        else:
            msg.set_content(html, subtype="html")
    for filename, data, mime in attachments:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


def run(raw: bytes, **kwargs: object) -> Report:
    return analyze(raw, **kwargs)  # type: ignore[arg-type]


def ids(report: Report) -> set[str]:
    return {f.rule.id for f in report.findings}


@pytest.fixture(autouse=True)
def _no_trusted_authserv(monkeypatch: pytest.MonkeyPatch) -> None:
    """analyze() reads DAYAG_TRUSTED_AUTHSERV; keep the developer's setting out of the tests."""
    monkeypatch.delenv("DAYAG_TRUSTED_AUTHSERV", raising=False)


@pytest.fixture
def sample_bytes():
    def load(name: str) -> bytes:
        sample = get_sample(name)
        assert sample is not None, name
        return sample.read()

    return load
