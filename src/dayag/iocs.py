"""Collect indicators of compromise and export them for other tools."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import uuid
from datetime import datetime
from typing import Any

from .context import Context
from .domains import defang, is_freemail, is_ip_literal, is_known_legit, matches_domain
from .headers import originating_ips
from .knowledge import CLICK_TRACKERS, IPFS_GATEWAYS, URL_SHORTENERS
from .model import Finding, Ioc, Report, Verdict
from .rules import Category, Severity

_NAMESPACE = uuid.UUID("6f1c2c7e-9a3b-4d5e-8f10-2b7c4d9e0a11")
# Hosts shared by many users: the URL is an indicator, the host is not.
_SHARED_SERVICES = CLICK_TRACKERS | URL_SHORTENERS | IPFS_GATEWAYS


def collect_iocs(ctx: Context, findings: list[Finding], verdict: Verdict) -> list[Ioc]:
    """Every indicator in the email, flagged when it is tied to the threat.

    Benign infrastructure (gmail.com, a brand's real domain, a newsletter
    click tracker) is listed but never flagged, so exports can be fed to a
    blocklist without blocking Google.
    """
    phishy = verdict.rank >= Verdict.LIKELY_PHISHING.rank
    sender_suspect = phishy or any(
        f.rule.category in (Category.SENDER, Category.AUTHENTICATION)
        and f.severity >= Severity.MEDIUM
        for f in findings
    )
    iocs: dict[tuple[str, str], Ioc] = {}

    def add(kind: str, value: str, context: str, flagged: bool) -> None:
        key = (kind, value.lower())
        if value and key not in iocs:
            iocs[key] = Ioc(kind, value, context, flagged)

    if ctx.sender:
        legit = is_known_legit(ctx.sender.domain)
        add("email", ctx.sender.address, "From", sender_suspect)
        if not legit and not is_freemail(ctx.sender.domain):
            add("domain", ctx.sender.domain, "From domain", sender_suspect)
    for reply in ctx.reply_to:
        add("email", reply.address, "Reply-To", sender_suspect)
        if reply.domain and not is_known_legit(reply.domain):
            add("domain", reply.domain, "Reply-To domain", sender_suspect)

    sender_infra_legit = not ctx.sender or is_known_legit(ctx.sender.domain)
    for index, ip in enumerate(originating_ips(ctx.hops)):
        kind = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ipv4"
        context = "originating IP" if index == 0 else "relay IP"
        add(kind, ip, context, phishy and index == 0 and not sender_infra_legit)

    for link in ctx.links:
        shared = is_known_legit(link.host) or matches_domain(link.host, _SHARED_SERVICES)
        flagged = bool(link.flags) or (phishy and not shared)
        add("url", link.url, f"link ({link.source})", flagged)
        if not link.host or shared:
            continue
        if is_ip_literal(link.host):
            try:
                kind = "ipv6" if ipaddress.ip_address(link.host).version == 6 else "ipv4"
            except ValueError:
                continue  # decimal or hex IP form
            add(kind, link.host, "link host", flagged)
        else:
            add("domain", link.host, "link host", flagged)

    for attachment in ctx.attachments:
        flagged = bool(attachment.flags) or phishy
        add("sha256", attachment.sha256, attachment.filename, flagged)
        add("md5", attachment.md5, attachment.filename, flagged)
    return list(iocs.values())


# --- Export -----------------------------------------------------------------


def iocs_to_csv(report: Report, defanged: bool = True) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["type", "value", "context", "flagged"])
    for ioc in report.iocs:
        defangable = ioc.type in ("url", "domain", "email", "ipv4")
        value = defang(ioc.value) if defanged and defangable else ioc.value
        writer.writerow([ioc.type, value, ioc.context, "yes" if ioc.flagged else "no"])
    return out.getvalue()


def iocs_to_json(report: Report) -> str:
    return json.dumps(
        [
            {"type": i.type, "value": i.value, "context": i.context, "flagged": i.flagged}
            for i in report.iocs
        ],
        indent=2,
        ensure_ascii=False,
    )


_STIX_PATTERNS = {
    "url": "[url:value = '{}']",
    "domain": "[domain-name:value = '{}']",
    "ipv4": "[ipv4-addr:value = '{}']",
    "ipv6": "[ipv6-addr:value = '{}']",
    "email": "[email-addr:value = '{}']",
    "sha256": "[file:hashes.'SHA-256' = '{}']",
    "md5": "[file:hashes.MD5 = '{}']",
}


def _stix_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def iocs_to_stix(report: Report) -> str:
    """A STIX 2.1 bundle of the flagged indicators, ready for a TIP such as MISP or OpenCTI."""
    created = _stix_time(report.analyzed_at)
    subject = report.summary.subject or "(no subject)"
    objects: list[dict[str, Any]] = []
    for ioc in report.iocs:
        if not ioc.flagged:
            continue
        escaped = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_NAMESPACE, f'{ioc.type}:{ioc.value}')}",
                "created": created,
                "modified": created,
                "name": f"{ioc.type}: {defang(ioc.value)}",
                "description": f"{ioc.context} in phishing email '{subject}' "
                f"(Dayag verdict: {report.verdict.label}, score {report.score}).",
                "indicator_types": ["malicious-activity"],
                "pattern": _STIX_PATTERNS[ioc.type].format(escaped),
                "pattern_type": "stix",
                "valid_from": created,
                "labels": ["phishing"],
            }
        )
    bundle_id = uuid.uuid5(_NAMESPACE, "|".join(sorted(str(o["id"]) for o in objects)) or "empty")
    return json.dumps(
        {"type": "bundle", "id": f"bundle--{bundle_id}", "objects": objects},
        indent=2,
        ensure_ascii=False,
    )
