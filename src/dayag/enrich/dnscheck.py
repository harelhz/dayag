"""Live DNS checks of the sender domain: DMARC policy and mail servers."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import dns.exception
import dns.resolver
import httpx

from ..config import Config
from ..context import Context
from ..domains import is_freemail, is_known_legit, registrable_domain
from ..model import Finding, LookupResult, hit

_NOT_FOUND = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    return resolver


def txt_records(name: str) -> list[str]:
    try:
        answer: Any = _resolver().resolve(name, "TXT")
    except _NOT_FOUND:
        return []
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


def has_mail_server(domain: str) -> bool:
    """MX records, or an A record (RFC 5321 implicit MX)."""
    for rdtype in ("MX", "A"):
        try:
            if len(_resolver().resolve(domain, rdtype)):
                return True
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return False
    return False


def lookup_dns(
    ctx: Context, config: Config, client: httpx.Client, now: datetime
) -> tuple[list[Finding], list[LookupResult]]:
    domain = ctx.sender_domain
    if not domain or is_freemail(domain) or is_known_legit(domain):
        return [], []
    findings: list[Finding] = []
    results: list[LookupResult] = []
    org = registrable_domain(domain)
    try:
        dmarc = [r for r in txt_records(f"_dmarc.{org}") if r.lower().startswith("v=dmarc1")]
        if dmarc:
            policy = re.search(r"\bp\s*=\s*(\w+)", dmarc[0], re.IGNORECASE)
            summary = f"DMARC policy p={policy.group(1).lower() if policy else '?'}"
            results.append(LookupResult("DNS", f"_dmarc.{org}", "ok", summary))
        else:
            results.append(LookupResult("DNS", f"_dmarc.{org}", "not found", "no DMARC record"))
            findings.append(hit("SENDER-NO-DMARC", f"{org} publishes no DMARC record."))
        if has_mail_server(domain):
            results.append(LookupResult("DNS", domain, "ok", "accepts email"))
        else:
            results.append(LookupResult("DNS", domain, "ok", "no MX or A record"))
            findings.append(hit("SENDER-NO-MX", f"{domain} has no mail server.", [domain]))
    except dns.exception.DNSException as error:
        results.append(LookupResult("DNS", org, "error", type(error).__name__))
    return findings, results
