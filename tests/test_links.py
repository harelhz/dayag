from __future__ import annotations

from urllib.parse import quote

import pytest
from conftest import build_email, ids, run

from dayag.urls import find_urls, make_link, unwrap


def links_report(html: str, **headers: str):
    return run(build_email(dict(headers), text=None, html=f"<html><body>{html}</body></html>"))


def test_find_urls_strips_trailing_punctuation() -> None:
    text = "Go to https://evil.example/login). Or www.other.example, now."
    assert find_urls(text) == ["https://evil.example/login", "http://www.other.example"]


@pytest.mark.parametrize(
    ("wrapped", "wrapper"),
    [
        (
            "https://eur03.safelinks.protection.outlook.com/?url="
            + quote("https://evil.example/a?b=1", safe="")
            + "&data=x&reserved=0",
            "Microsoft Safe Links",
        ),
        (
            "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a-3Fb-3D1&d=x",
            "Proofpoint URL Defense",
        ),
        (
            "https://urldefense.com/v3/__https://evil.example/a?b=1__;!!abc$",
            "Proofpoint URL Defense",
        ),
        ("https://www.google.com/url?q=https://evil.example/a?b%3D1&sa=D", "Google redirect"),
    ],
)
def test_unwrap(wrapped: str, wrapper: str) -> None:
    url, name = unwrap(wrapped)
    assert name == wrapper
    assert url.startswith("https://evil.example/a")


def test_make_link_ignores_mailto_and_relative() -> None:
    assert make_link("mailto:a@b.example") is None
    assert make_link("/relative/path") is None
    link = make_link("javascript:alert(1)")
    assert link is not None and link.host == ""


def test_text_mismatch() -> None:
    report = links_report('<a href="https://evil.example/x">https://www.mybank.com/login</a>')
    assert "LINK-TEXT-MISMATCH" in ids(report)


def test_text_mismatch_ignores_newsletter_click_tracking() -> None:
    report = links_report(
        '<a href="https://contoso.us1.list-manage.com/track/click?u=1">www.contoso.com</a>'
    )
    assert "LINK-TEXT-MISMATCH" not in ids(report)


def test_text_mismatch_ignores_file_names_in_text() -> None:
    report = links_report('<a href="https://contoso.com/files/1">report.pdf</a>')
    assert "LINK-TEXT-MISMATCH" not in ids(report)


@pytest.mark.parametrize(
    ("href", "rule"),
    [
        ("http://198.51.100.9/login", "LINK-IP"),
        ("http://3232235777/", "LINK-IP"),
        ("https://www.paypal.com@evil.example/", "LINK-USERINFO"),
        ("https://bit.ly/abc", "LINK-SHORTENER"),
        ("https://ipfs.io/ipfs/QmYwAPJzv5CZsnAzt8auVTL", "LINK-IPFS"),
        ("https://evil.netlify.app/", "LINK-FREE-HOSTING"),
        ("https://docs.google.com/forms/d/e/1FAIpQL/viewform", "LINK-FREE-HOSTING"),
        ("https://evil.zip/", "LINK-RISKY-TLD"),
        ("https://evil.example:8443/", "LINK-NONSTANDARD-PORT"),
        ("https://xn--pypal-4ve.com/", "LINK-LOOKALIKE"),
        ("https://paypal-verify.com/", "LINK-COMBOSQUAT"),
        ("javascript:alert(document.cookie)", "LINK-SCRIPT-SCHEME"),
        ("https://unrelated.example/account/verify", "LINK-CREDENTIAL-PATH"),
    ],
)
def test_link_rules(href: str, rule: str) -> None:
    report = links_report(f'<a href="{href}">click here</a>')
    assert rule in ids(report)


def test_links_to_own_domain_are_not_login_pages() -> None:
    report = links_report('<a href="https://contoso.com/account/login">Sign in</a>')
    assert "LINK-CREDENTIAL-PATH" not in ids(report)


def test_links_in_text_body_are_found() -> None:
    report = run(build_email(text="Pay here: http://198.51.100.9/pay"))
    assert "LINK-IP" in ids(report)


def test_html_forms_and_password_fields() -> None:
    report = links_report(
        '<form action="https://evil.example/collect"><input type="password" name="p"></form>'
    )
    assert {"CONTENT-FORM", "CONTENT-PASSWORD-FIELD"} <= ids(report)
    assert any(link.url == "https://evil.example/collect" for link in report.links)


def test_each_rule_counts_once_however_many_links() -> None:
    many = "".join(f'<a href="https://bit.ly/{i}">x</a>' for i in range(20))
    report = links_report(many)
    shortener = [f for f in report.findings if f.rule.id == "LINK-SHORTENER"]
    assert len(shortener) == 1
    assert len(shortener[0].evidence) == 20
