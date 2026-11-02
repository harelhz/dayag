"""End-to-end expectations for every bundled sample."""

from __future__ import annotations

import pytest
from conftest import ids, run

from dayag.demo import SAMPLES
from dayag.model import Verdict

EXPECTED = {
    "01-github-notification.eml": (Verdict.CLEAN, {"AUTH-DMARC-PASS", "CONTENT-TRACKING-PIXEL"}),
    "02-paypal-homoglyph.eml": (
        Verdict.MALICIOUS,
        {
            "LINK-LOOKALIKE",
            "LINK-TEXT-MISMATCH",
            "LINK-PUNYCODE",
            "SENDER-COMBOSQUAT",
            "SENDER-DISPLAY-BRAND",
            "CONTENT-CREDENTIALS",
            "CONTENT-URGENCY",
        },
    ),
    "03-html-smuggling-invoice.eml": (
        Verdict.MALICIOUS,
        {
            "ATT-HTML-SMUGGLING",
            "ATT-DOUBLE-EXT",
            "ATT-HTML",
            "CONTENT-FAKE-REPLY",
            "SENDER-FREEMAIL",
        },
    ),
    "04-ceo-fraud.eml": (
        Verdict.LIKELY_PHISHING,
        {"SENDER-REPLYTO-FREEMAIL", "CONTENT-PAYMENT", "CONTENT-URGENCY", "SENDER-FREEMAIL"},
    ),
    "05-israel-post-customs.eml": (
        Verdict.MALICIOUS,
        {
            "SENDER-COMBOSQUAT",
            "SENDER-DISPLAY-BRAND",
            "AUTH-COMPAUTH-FAIL",
            "LINK-IP",
            "LINK-SHORTENER",
            "LINK-NONSTANDARD-PORT",
            "LINK-RISKY-TLD",
            "INFRA-PHP-SCRIPT",
            "INFRA-MAILER",
            "CONTENT-PAYMENT",
            "CONTENT-GENERIC-GREETING",
        },
    ),
    "06-reported-m365-phish.eml": (
        Verdict.MALICIOUS,
        {
            "META-REPORTED",
            "SENDER-LOOKALIKE",
            "SENDER-DISPLAY-BRAND",
            "LINK-FREE-HOSTING",
            "LINK-COMBOSQUAT",
            "ATT-ENCRYPTED-ARCHIVE",
            "ATT-ARCHIVE-RISKY",
        },
    ),
    "07-dhl-shipping-documents.eml": (
        Verdict.MALICIOUS,
        {
            "AUTH-DMARC-FAIL",
            "AUTH-SPF-FAIL",
            "AUTH-FORGED-RESULTS",
            "ATT-REMOTE-TEMPLATE",
            "ATT-PDF-ACTIVE",
            "SENDER-COMBOSQUAT",
            "LINK-IP",
        },
    ),
}


def test_every_sample_has_expectations() -> None:
    assert {s.name for s in SAMPLES} == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample(name: str, sample_bytes) -> None:
    verdict, expected_rules = EXPECTED[name]
    report = run(sample_bytes(name))
    assert report.verdict is verdict
    missing = expected_rules - ids(report)
    assert not missing, f"missing {missing}, got {sorted(ids(report))}"


def test_legitimate_sample_has_no_risk_points(sample_bytes) -> None:
    report = run(sample_bytes("01-github-notification.eml"))
    assert all(f.rule.points <= 0 for f in report.findings)
    assert not any(i.flagged for i in report.iocs)


def test_safe_links_are_unwrapped(sample_bytes) -> None:
    report = run(sample_bytes("06-reported-m365-phish.eml"))
    link = next(link for link in report.links if link.wrapped_by)
    assert link.wrapped_by == "Microsoft Safe Links"
    assert link.host == "m365-login-portal.web.app"
    assert "safelinks" in link.original


def test_reported_wrapper_can_be_analysed_itself(sample_bytes) -> None:
    report = run(sample_bytes("06-reported-m365-phish.eml"), unwrap=False)
    assert "META-REPORTED" not in ids(report)
    assert report.summary.subject.startswith("FW:")


def test_pdf_links_include_compressed_streams(sample_bytes) -> None:
    report = run(sample_bytes("07-dhl-shipping-documents.eml"))
    urls = {link.url for link in report.links}
    assert "https://dhl-express-billing.com/receipt/download" in urls  # inside a FlateDecode stream
    assert "http://dhl-express-billing.com/receipt/view?id=88231" in urls


def test_hebrew_sample_is_decoded(sample_bytes) -> None:
    report = run(sample_bytes("05-israel-post-customs.eml"))
    assert "דואר ישראל" in report.summary.sender
    assert "דמי מכס" in report.summary.subject
