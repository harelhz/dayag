"""The analysis pipeline: parse -> extract -> check -> (look up) -> score -> report."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import httpx

from . import __version__
from .checks import ALL_CHECKS
from .config import Config
from .context import Context, build_context
from .iocs import collect_iocs
from .model import EmailSummary, Finding, LookupResult, Report, hit
from .parsing import extract, find_reported_message, load_message
from .scoring import merge_findings, score, verdict_for
from .text import for_display

PREVIEW_CHARS = 4000


def analyze(
    raw: bytes,
    *,
    online: bool = False,
    config: Config | None = None,
    unwrap: bool = True,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> Report:
    """Analyse one email (RFC 5322 bytes, e.g. a saved .eml file)."""
    started = time.perf_counter()
    now = now or datetime.now(UTC)
    message = load_message(raw)
    findings: list[Finding] = []
    wrapper_subject = ""
    if unwrap and (inner := find_reported_message(message)) is not None:
        outer = extract(message, len(raw))
        wrapper_subject = outer.header("Subject") or "(no subject)"
        reporter = outer.header("From")
        findings.append(
            hit(
                "META-REPORTED",
                f'"{wrapper_subject}" from {reporter or "an unknown sender"} is a report '
                "wrapper; the attached original email was analysed.",
            )
        )
        message = inner

    email = extract(message, len(raw))
    ctx = build_context(email)
    for check in ALL_CHECKS:
        findings += check(ctx)

    lookups: list[LookupResult] = []
    if online:
        from .enrich import run_lookups  # imported lazily: offline use needs no network code

        found, lookups = run_lookups(ctx, config or Config.from_env(), client=client, now=now)
        findings += found

    merged = merge_findings(findings)
    total = score(merged)
    verdict = verdict_for(total)
    return Report(
        tool_version=__version__,
        analyzed_at=now,
        verdict=verdict,
        score=total,
        summary=_summary(ctx),
        findings=merged,
        auth=ctx.auth,
        links=ctx.links,
        attachments=ctx.attachments,
        hops=ctx.hops,
        iocs=collect_iocs(ctx, merged, verdict),
        lookups=lookups,
        body_preview=_preview(ctx),
        reported_wrapper=wrapper_subject,
        online=online,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )


def _summary(ctx: Context) -> EmailSummary:
    email = ctx.email
    return EmailSummary(
        subject=email.header("Subject"),
        sender=str(ctx.sender) if ctx.sender else email.header("From"),
        to=email.header("To"),
        cc=email.header("Cc"),
        date=email.header("Date"),
        message_id=email.header("Message-ID"),
        reply_to=", ".join(str(a) for a in ctx.reply_to),
        return_path=ctx.return_path,
        size=email.size,
    )


def _preview(ctx: Context) -> str:
    """The body as plain text. HTML is never rendered: it could load remote
    content (confirming the address is live) or run in the analyst's browser."""
    text = next((t for t in ctx.email.text_bodies if t.strip()), "") or ctx.html.text
    return for_display(text.strip(), PREVIEW_CHARS)
