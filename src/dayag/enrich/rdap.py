"""Domain age from RDAP, the JSON successor to WHOIS. No API key needed."""

from __future__ import annotations

from datetime import datetime

import httpx

from ..config import Config
from ..context import Context
from ..model import Finding, LookupResult, hit
from .targets import domains_to_check

RDAP_URL = "https://rdap.org/domain/{}"
NEW_DOMAIN_DAYS = 30


def _registration_date(data: dict[str, object]) -> datetime | None:
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.fromisoformat(
                    str(event.get("eventDate", "")).replace("Z", "+00:00")
                )
            except ValueError:
                return None
    return None


def lookup_rdap(
    ctx: Context, config: Config, client: httpx.Client, now: datetime
) -> tuple[list[Finding], list[LookupResult]]:
    findings: list[Finding] = []
    results: list[LookupResult] = []
    for domain, role in domains_to_check(ctx, config.max_domain_lookups):
        try:
            response = client.get(RDAP_URL.format(domain))
            if response.status_code == 404:
                results.append(LookupResult("RDAP", domain, "not found", "no RDAP record"))
                continue
            response.raise_for_status()
            registered = _registration_date(response.json())
        except (httpx.HTTPError, ValueError) as error:
            results.append(LookupResult("RDAP", domain, "error", type(error).__name__))
            continue
        if registered is None:
            results.append(LookupResult("RDAP", domain, "ok", "registration date not published"))
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=now.tzinfo)
        age = (now - registered).days
        results.append(
            LookupResult("RDAP", domain, "ok", f"registered {registered:%Y-%m-%d} ({age} days ago)")
        )
        if age < NEW_DOMAIN_DAYS:
            rule = "SENDER-NEW-DOMAIN" if role == "sender" else "LINK-NEW-DOMAIN"
            findings.append(
                hit(
                    rule,
                    f"{domain} was registered {age} days ago, on {registered:%Y-%m-%d}.",
                    [domain],
                )
            )
    return findings, results
