from __future__ import annotations

import pytest

from dayag.domains import (
    defang,
    edit_distance,
    find_lookalike,
    is_freemail,
    matches_domain,
    registrable_domain,
    skeleton,
    to_unicode,
)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.paypal.com", "paypal.com"),
        ("a.b.paypal.co.uk", "paypal.co.uk"),
        ("btl.gov.il", "btl.gov.il"),
        ("evil.web.app", "evil.web.app"),  # private suffix: the label belongs to the attacker
        ("198.51.100.7", "198.51.100.7"),
        ("LOGIN.PayPal.COM.", "paypal.com"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    ("host", "technique", "brand"),
    [
        ("xn--pypal-4ve.com", "homoglyph", "PayPal"),  # Cyrillic а
        ("paypa1.com", "character swap", "PayPal"),
        ("rnicrosoft.com", "character swap", "Microsoft"),
        ("micros0ft-security.com", "character swap", "Microsoft"),
        ("paypall.com", "typo", "PayPal"),
        ("pyapal.com", "typo", "PayPal"),
        ("netflx.com", "typo", "Netflix"),
        ("paypal.xyz", "different TLD", "PayPal"),
        ("secure-paypal.net", "brand name in domain", "PayPal"),
        ("mypaypalaccount.com", "brand name in domain", "PayPal"),
        ("israelpost-delivery.top", "brand name in domain", "Israel Post"),
        ("paypal.com.verify-account.xyz", "brand name in subdomain", "PayPal"),
        ("m365-login-portal.web.app", "brand name in domain", "Microsoft"),
        ("paypal-login.s3.amazonaws.com", "brand name in domain", "PayPal"),
    ],
)
def test_lookalikes(host: str, technique: str, brand: str) -> None:
    match = find_lookalike(host)
    assert match is not None, host
    assert (match.technique, match.brand.name) == (technique, brand)


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",
        "www.paypal.com",
        "login.microsoftonline.com",
        "sites.google.com",
        "gmail.com",
        "outlook.com",
        "amazonaws.com",
        "google-analytics.com",
        "github.com",
        # Ordinary words one edit away from a brand must not be typosquats.
        "finance.com",
        "cloud.com",
        "apply.com",
        "phase.com",
        "my-cloud.com",
        "finance-dept.com",
        "example.com",
        "contoso.com",
        "198.51.100.7",
    ],
)
def test_not_lookalikes(host: str) -> None:
    assert find_lookalike(host) is None


def test_strong_vs_weak_lookalikes() -> None:
    strong = find_lookalike("paypa1.com")
    weak = find_lookalike("paypal-support.com")
    assert strong is not None and strong.strong
    assert weak is not None and not weak.strong


def test_skeleton_folds_lookalike_characters() -> None:
    assert skeleton("pаypal") == skeleton("paypal") == skeleton("paypa1")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("gооgle") == skeleton("google")  # Cyrillic о


def test_edit_distance_counts_transpositions_as_one() -> None:
    assert edit_distance("paypal", "pyapal") == 1
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("abc", "xyz") == 3


def test_to_unicode() -> None:
    assert to_unicode("www.xn--pypal-4ve.com") == "www.pаypal.com"


def test_matches_domain() -> None:
    assert matches_domain("a.b.example.com", frozenset({"example.com"}))
    assert not matches_domain("badexample.com", frozenset({"example.com"}))


def test_freemail() -> None:
    assert is_freemail("gmail.com")
    assert not is_freemail("contoso.com")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://evil.example/path.php", "hxxps://evil[.]example/path.php"),
        ("evil.example", "evil[.]example"),
        ("a@evil.example", "a[@]evil[.]example"),
        ("198.51.100.7", "198[.]51[.]100[.]7"),
    ],
)
def test_defang(value: str, expected: str) -> None:
    assert defang(value) == expected
