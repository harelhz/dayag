"""AbuseIPDB reputation of the IP that sent the email."""

from __future__ import annotations

from datetime import datetime

import httpx

from ..config import Config
from ..context import Context
from ..headers import originating_ips
from ..model import Finding, LookupResult, hit

API = "https://api.abuseipdb.com/api/v2/check"
MIN_CONFIDENCE = 25


def lookup_abuseipdb(
    ctx: Context, config: Config, client: httpx.Client, now: datetime
) -> tuple[list[Finding], list[LookupResult]]:
    ips = originating_ips(ctx.hops)[:1]
    if not ips:
        return [], []
    if not config.abuseipdb_key:
        return [], [
            LookupResult("AbuseIPDB", ips[0], "skipped", "set DAYAG_ABUSEIPDB_KEY to enable")
        ]
    findings: list[Finding] = []
    results: list[LookupResult] = []
    for ip in ips:
        try:
            response = client.get(
                API,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": config.abuseipdb_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()["data"]
            confidence = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            results.append(LookupResult("AbuseIPDB", ip, "error", type(error).__name__))
            continue
        where = ", ".join(str(v) for v in (data.get("countryCode"), data.get("isp")) if v)
        summary = f"confidence {confidence}%, {reports} reports" + (f" ({where})" if where else "")
        results.append(LookupResult("AbuseIPDB", ip, "ok", summary))
        if confidence >= MIN_CONFIDENCE:
            findings.append(
                hit(
                    "INFRA-IP-REPUTATION",
                    f"{ip} has an abuse confidence of {confidence}% from {reports} reports.",
                    [ip],
                )
            )
    return findings, results
