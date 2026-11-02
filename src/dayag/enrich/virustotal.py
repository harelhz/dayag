"""VirusTotal reputation of attachments, links and domains.

Read-only: GET requests for existing reports. Nothing is uploaded or
submitted for scanning, so a targeted email is never shared with VirusTotal's
customers.
"""

from __future__ import annotations

import base64
from datetime import datetime

import httpx

from ..config import Config
from ..context import Context
from ..domains import defang
from ..model import Finding, LookupResult, hit
from .targets import domains_to_check

API = "https://www.virustotal.com/api/v3"
MIN_DETECTIONS = 2


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def lookup_virustotal(
    ctx: Context, config: Config, client: httpx.Client, now: datetime
) -> tuple[list[Finding], list[LookupResult]]:
    if not config.virustotal_key:
        return [], [
            LookupResult("VirusTotal", "-", "skipped", "set DAYAG_VIRUSTOTAL_KEY to enable")
        ]

    # (rule, display target, API path), most valuable first.
    targets = [
        ("ATT-REPUTATION", a.filename, f"files/{a.sha256}") for a in ctx.attachments if not a.inline
    ]
    targets += [
        ("LINK-REPUTATION", defang(link.url), f"urls/{_url_id(link.url)}")
        for link in ctx.links
        if link.flags and link.host
    ]
    targets += [
        ("LINK-REPUTATION", domain, f"domains/{domain}")
        for domain, _ in domains_to_check(ctx, config.max_domain_lookups)
    ]

    findings: list[Finding] = []
    results: list[LookupResult] = []
    headers = {"x-apikey": config.virustotal_key}
    for rule, target, path in targets[: config.max_virustotal_lookups]:
        try:
            response = client.get(f"{API}/{path}", headers=headers)
            if response.status_code == 404:
                results.append(LookupResult("VirusTotal", target, "not found", "never seen"))
                continue
            if response.status_code == 429:
                results.append(LookupResult("VirusTotal", target, "error", "rate limited"))
                break
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            results.append(LookupResult("VirusTotal", target, "error", type(error).__name__))
            continue
        bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        results.append(LookupResult("VirusTotal", target, "ok", f"{bad}/{total} engines flag it"))
        if bad >= MIN_DETECTIONS:
            findings.append(hit(rule, f"{bad} of {total} engines flag {target}.", [target]))
    return findings, results
