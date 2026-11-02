"""Render reports in the terminal with rich.

Email content is wrapped in Text objects (never parsed as rich markup) and
stripped of control characters, so a subject like "[bold]" or one carrying
terminal escape sequences prints as plain text.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..domains import defang
from ..model import Report, Verdict
from ..rules import Severity
from ..text import for_display
from .html import filesize

VERDICT_STYLE = {
    Verdict.CLEAN: "bold green",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.LIKELY_PHISHING: "bold dark_orange",
    Verdict.MALICIOUS: "bold red",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
AUTH_STYLE = {"pass": "green", "fail": "red", "softfail": "yellow", "none": "dim"}


def _t(value: object, limit: int | None = None, style: str = "") -> Text:
    return Text(for_display(str(value or ""), limit), style=style)


def _header(report: Report) -> Panel:
    verdict = Text.assemble(
        (report.verdict.label.upper(), VERDICT_STYLE[report.verdict]),
        ("   score ", "dim"),
        (f"{report.score}", "bold"),
        ("/100", "dim"),
    )
    rows = Table.grid(padding=(0, 2))
    rows.add_column(style="dim", no_wrap=True)
    rows.add_column()
    summary = report.summary
    rows.add_row("Subject", _t(summary.subject or "(no subject)", 200))
    rows.add_row("From", _t(summary.sender, 200))
    if summary.reply_to:
        rows.add_row("Reply-To", _t(summary.reply_to, 200))
    rows.add_row("To", _t(summary.to or "-", 200))
    rows.add_row("Date", _t(summary.date or "-"))
    auth = report.auth
    auth_line = Text()
    for name, result in (
        ("SPF", auth.spf),
        ("DKIM", auth.dkim),
        ("DMARC", auth.dmarc),
        ("CompAuth", auth.compauth),
    ):
        if name == "CompAuth" and not result:
            continue
        auth_line.append(f"{name} ", style="dim")
        auth_line.append(result or "-", style=AUTH_STYLE.get(result, "yellow"))
        auth_line.append("   ")
    rows.add_row("Auth", auth_line)
    if report.reported_wrapper:
        rows.add_row("Note", _t(f"unwrapped from report: {report.reported_wrapper}", 200, "dim"))
    return Panel(
        Group(verdict, Text(), rows),
        title="Dayag",
        title_align="left",
        border_style=VERDICT_STYLE[report.verdict].replace("bold ", ""),
        box=box.ROUNDED,
    )


def _findings(report: Report) -> Table:
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, expand=True, pad_edge=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Pts", justify="right", no_wrap=True)
    table.add_column("Finding", ratio=1)
    for finding in report.findings:
        cell = Text.assemble((finding.rule.title, "bold"), ("  " + finding.rule.id, "dim"), "\n")
        cell.append_text(_t(finding.detail, 400))
        for item in finding.evidence[:3]:
            cell.append("\n  ")
            cell.append_text(_t(item, 160, "dim"))
        if len(finding.evidence) > 3:
            cell.append(f"\n  and {len(finding.evidence) - 3} more", style="dim")
        table.add_row(
            Text(f" {finding.severity.label} ", style=SEVERITY_STYLE[finding.severity]),
            Text(f"{finding.rule.points:+d}", style="dim"),
            cell,
        )
    return table


def _links(report: Report, verbose: bool) -> Table | None:
    links = report.links if verbose else [link for link in report.links if link.flags]
    if not links:
        return None
    table = Table(
        title="Links" if verbose else "Flagged links",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        show_edge=False,
        expand=True,
        pad_edge=False,
    )
    table.add_column("Destination (defanged)", ratio=3, overflow="fold")
    table.add_column("Flags", ratio=2)
    for link in links:
        destination = _t(defang(link.url), 300)
        if link.wrapped_by:
            destination.append(f"\nunwrapped from {link.wrapped_by}", style="dim")
        table.add_row(
            destination, _t(", ".join(link.flags) or "-", style="red" if link.flags else "dim")
        )
    return table


def _attachments(report: Report) -> Table | None:
    if not report.attachments:
        return None
    table = Table(
        title="Attachments",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        show_edge=False,
        expand=True,
        pad_edge=False,
    )
    table.add_column("Name", ratio=2, overflow="fold")
    table.add_column("Really is", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("SHA-256", ratio=2, overflow="fold")
    table.add_column("Flags", ratio=2)
    for a in report.attachments:
        table.add_row(
            _t(a.filename, 200),
            a.kind,
            filesize(a.size),
            Text(a.sha256, style="dim"),
            _t(", ".join(a.flags) or "-", style="red" if a.flags else "dim"),
        )
    return table


def _hops(report: Report) -> Table | None:
    if not report.hops:
        return None
    table = Table(
        title="Mail path (oldest first)",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        show_edge=False,
        expand=True,
        pad_edge=False,
    )
    for column in ("#", "From", "IP", "By"):
        table.add_column(column, overflow="fold")
    for hop in report.hops:
        table.add_row(
            str(hop.number), _t(hop.from_host or "-", 80), hop.ip or "-", _t(hop.by_host or "-", 80)
        )
    return table


def render_terminal(report: Report, console: Console, verbose: bool = False) -> None:
    console.print(_header(report))
    if report.findings:
        console.print(_findings(report))
    for table in (
        _links(report, verbose),
        _attachments(report),
        _hops(report) if verbose else None,
    ):
        if table is not None:
            console.print(table)
    if report.lookups:
        lookups = Table(
            title="Online lookups",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            show_edge=False,
            expand=True,
            pad_edge=False,
        )
        for column in ("Source", "Target", "Result"):
            lookups.add_column(column, overflow="fold")
        for lookup in report.lookups:
            lookups.add_row(lookup.source, _t(lookup.target, 120), _t(lookup.summary, 200))
        console.print(lookups)
    flagged = sum(1 for i in report.iocs if i.flagged)
    console.print(
        Text(
            f"{flagged} flagged indicator(s) of {len(report.iocs)}. "
            "Export with --iocs FILE (csv, json or stix).",
            style="dim",
        )
    )
