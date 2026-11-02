"""Judge every link in the email and its attachments."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..context import Context
from ..domains import (
    brand_owning,
    defang,
    find_lookalike,
    has_public_suffix,
    is_free_hosting,
    is_ip_literal,
    matches_domain,
    registrable_domain,
    split_host,
    to_unicode,
)
from ..knowledge import CLICK_TRACKERS, IPFS_GATEWAYS, RISKY_TLDS, URL_SHORTENERS
from ..model import Finding, Link, hit

_DOMAIN_IN_TEXT = re.compile(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[/:?#\s]|$)")
_CREDENTIAL_PATH = re.compile(
    r"(?i)log-?in|sign-?in|logon|verif|account|passw|secure|update|auth|webmail|wallet|unlock"
)


def _flag(link: Link, findings: list[Finding], rule_id: str, detail: str, flag: str) -> None:
    findings.append(hit(rule_id, detail, [defang(link.url)]))
    if flag not in link.flags:
        link.flags.append(flag)


def _check_link(link: Link, sender_domain: str) -> list[Finding]:
    findings: list[Finding] = []
    if not link.host:
        _flag(
            link,
            findings,
            "LINK-SCRIPT-SCHEME",
            f"A link uses the {link.url.split(':', 1)[0].lower()}: scheme.",
            "script link",
        )
        return findings

    try:
        parts = urlsplit(link.url)
        port = parts.port
    except ValueError:
        parts, port = urlsplit(""), None

    host = link.host
    # How the victim sees it: www.xn--pypal-4ve.com is displayed as www.pаypal.com.
    shown_host = host if to_unicode(host) == host else f"{host} ({to_unicode(host)})"
    if is_ip_literal(host):
        _flag(link, findings, "LINK-IP", f"A link goes to the IP address {host}.", "IP address")
    if parts.username is not None or "@" in parts.netloc:
        _flag(
            link,
            findings,
            "LINK-USERINFO",
            f"The part before @ is ignored; the link really goes to {host}.",
            "@ trick",
        )
    if any(label.startswith("xn--") for label in host.split(".")):
        _flag(
            link,
            findings,
            "LINK-PUNYCODE",
            f"{host} is an internationalised domain name, displayed as {to_unicode(host)}.",
            "punycode",
        )

    lookalike = find_lookalike(host)
    if lookalike:
        if lookalike.strong:
            _flag(
                link,
                findings,
                "LINK-LOOKALIKE",
                f"{shown_host} is a {lookalike.describe()}.",
                f"lookalike of {lookalike.brand.domains[0]}",
            )
        else:
            _flag(
                link,
                findings,
                "LINK-COMBOSQUAT",
                f"{host} is a {lookalike.describe()}.",
                f"uses {lookalike.brand.name} name",
            )

    if matches_domain(host, URL_SHORTENERS):
        _flag(link, findings, "LINK-SHORTENER", f"{host} is a URL shortener.", "shortener")
    if matches_domain(host, IPFS_GATEWAYS) or re.search(r"/ipfs/(?:Qm|baf)", parts.path):
        _flag(link, findings, "LINK-IPFS", f"{host} serves content from IPFS.", "IPFS")
    elif is_free_hosting(host) or (host == "docs.google.com" and "/forms/" in parts.path):
        _flag(
            link,
            findings,
            "LINK-FREE-HOSTING",
            f"{host} is a free hosting or file-sharing service.",
            "free hosting",
        )

    suffix = split_host(host)[2]
    tld = suffix.rpartition(".")[2]
    if tld in RISKY_TLDS:
        _flag(
            link, findings, "LINK-RISKY-TLD", f"{host} uses the .{tld} top-level domain.", f".{tld}"
        )
    if port not in (None, 80, 443):
        _flag(link, findings, "LINK-NONSTANDARD-PORT", f"A link uses port {port}.", f"port {port}")

    shown = _DOMAIN_IN_TEXT.search(link.text) if link.text else None
    if shown and has_public_suffix(shown.group(1)):
        shown_domain = registrable_domain(shown.group(1))
        if shown_domain != link.domain and not matches_domain(host, CLICK_TRACKERS):
            _flag(
                link,
                findings,
                "LINK-TEXT-MISMATCH",
                f"The link text shows {shown_domain} but the link goes to {host}.",
                f"text says {shown_domain}",
            )

    unrelated = (
        link.domain != registrable_domain(sender_domain)
        and brand_owning(host) is None
        and not matches_domain(host, CLICK_TRACKERS)
    )
    if unrelated and _CREDENTIAL_PATH.search(parts.path + "?" + parts.query):
        _flag(
            link, findings, "LINK-CREDENTIAL-PATH", f"A login-themed page on {host}.", "login page"
        )
    return findings


def check_links(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for link in ctx.links:
        findings += _check_link(link, ctx.sender_domain)
    return findings
