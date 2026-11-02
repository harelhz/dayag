"""Optional online lookups (--online).

Off by default: analysing an email must not tip off the attacker or leak a
targeted email to third parties. Even when enabled, Dayag only *reads*
existing data (DNS, RDAP, VirusTotal and AbuseIPDB reports). It never
submits files or URLs, never visits links and never loads images.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from .. import __version__
from ..config import Config
from ..context import Context
from ..model import Finding, LookupResult, hit
from .abuseipdb import lookup_abuseipdb
from .dnscheck import lookup_dns
from .rdap import lookup_rdap
from .virustotal import lookup_virustotal

USER_AGENT = f"dayag/{__version__} (+https://github.com/harelhz/dayag)"

Lookup = Callable[
    [Context, Config, httpx.Client, datetime], tuple[list[Finding], list[LookupResult]]
]
LOOKUPS: tuple[Lookup, ...] = (lookup_dns, lookup_rdap, lookup_virustotal, lookup_abuseipdb)


def run_lookups(
    ctx: Context,
    config: Config,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> tuple[list[Finding], list[LookupResult]]:
    now = now or datetime.now(UTC)
    own_client = client is None
    http = client or httpx.Client(
        timeout=config.timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True
    )
    findings: list[Finding] = []
    results: list[LookupResult] = []
    try:
        for lookup in LOOKUPS:
            found, done = lookup(ctx, config, http, now)
            findings += found
            results += done
    finally:
        if own_client:
            http.close()
    failed = [r for r in results if r.status == "error"]
    if failed:
        findings.append(
            hit(
                "META-LOOKUP-FAILED",
                f"{len(failed)} online lookup(s) failed.",
                [f"{r.source} {r.target}: {r.summary}" for r in failed],
            )
        )
    return findings, results
