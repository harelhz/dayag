"""Command line interface: dayag analyze | samples | rules | serve."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .analyzer import analyze
from .config import Config
from .demo import SAMPLES, SAMPLES_DIR
from .iocs import iocs_to_csv, iocs_to_json, iocs_to_stix
from .model import Report, Verdict
from .parsing import EmailTooLarge
from .render.html import render_html
from .render.terminal import VERDICT_STYLE, render_terminal
from .rules import RULES, detections_markdown

EXIT_OK, EXIT_THRESHOLD, EXIT_ERROR = 0, 1, 2
IOC_EXPORTERS = {"csv": iocs_to_csv, "json": iocs_to_json, "stix": iocs_to_stix}


def _read(source: str) -> bytes:
    if source == "-":
        return sys.stdin.buffer.read()
    return Path(source).read_bytes()


def _ioc_format(path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    return "json" if path.lower().endswith(".json") else "csv"


def cmd_analyze(args: argparse.Namespace) -> int:
    console = Console(highlight=False)
    errors = Console(stderr=True, highlight=False)
    config = Config.from_env()
    reports: list[tuple[str, Report]] = []
    status = EXIT_OK
    for source in args.files:
        try:
            report = analyze(
                _read(source), online=args.online, config=config, unwrap=not args.no_unwrap
            )
        except (OSError, EmailTooLarge) as error:
            errors.print(Text(f"{source}: {error}", style="red"))
            status = EXIT_ERROR
            continue
        reports.append((source, report))
        if args.json:
            continue
        if len(args.files) > 1:
            console.rule(Text(source, style="bold"))
        render_terminal(report, console, verbose=args.verbose)

    if args.json:
        payload = [r.to_dict() | {"file": s} for s, r in reports]
        print(
            json.dumps(
                payload[0] if len(args.files) == 1 and payload else payload,
                indent=2,
                ensure_ascii=False,
            )
        )
    elif len(reports) > 1:
        console.print(_summary_table(reports))

    if len(reports) == 1:
        report = reports[0][1]
        if args.html:
            Path(args.html).write_text(render_html(report), encoding="utf-8")
            errors.print(Text(f"HTML report written to {args.html}", style="dim"))
        if args.iocs:
            exporter = IOC_EXPORTERS[_ioc_format(args.iocs, args.ioc_format)]
            Path(args.iocs).write_text(exporter(report), encoding="utf-8")
            errors.print(Text(f"Indicators written to {args.iocs}", style="dim"))

    if args.fail_on and status == EXIT_OK:
        threshold = Verdict(args.fail_on).rank
        if any(r.verdict.rank >= threshold for _, r in reports):
            status = EXIT_THRESHOLD
    return status


def _summary_table(reports: list[tuple[str, Report]]) -> Table:
    table = Table(title="Summary", title_justify="left", box=box.SIMPLE_HEAD)
    table.add_column("File", overflow="fold")
    table.add_column("Verdict")
    table.add_column("Score", justify="right")
    table.add_column("Top finding", overflow="fold")
    for source, report in reports:
        top = report.findings[0].rule.title if report.findings else "-"
        table.add_row(
            source,
            Text(report.verdict.label, style=VERDICT_STYLE[report.verdict]),
            str(report.score),
            top,
        )
    return table


def cmd_samples(args: argparse.Namespace) -> int:
    table = Table(
        title="Bundled samples (synthetic and harmless)", title_justify="left", box=box.SIMPLE_HEAD
    )
    table.add_column("Sample")
    table.add_column("Verdict")
    table.add_column("Score", justify="right")
    table.add_column("File", style="dim")
    for sample in SAMPLES:
        report = analyze(sample.read())
        table.add_row(
            sample.title,
            Text(report.verdict.label, style=VERDICT_STYLE[report.verdict]),
            str(report.score),
            sample.name,
        )
    console = Console(highlight=False)
    console.print(table)
    console.print(Text(f"Folder: {SAMPLES_DIR}", style="dim"))
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    if args.markdown:
        print(detections_markdown())
        return EXIT_OK
    table = Table(box=box.SIMPLE_HEAD, title=f"{len(RULES)} detection rules", title_justify="left")
    for column in ("ID", "Finding", "Severity", "Points", "ATT&CK"):
        table.add_column(column)
    for rule in RULES.values():
        title = rule.title + (" (online)" if rule.online else "")
        table.add_row(
            rule.id, title, rule.severity.label, f"{rule.points:+d}", ", ".join(rule.attack)
        )
    Console(highlight=False).print(table)
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from .web.app import create_app
    except ImportError:
        print("The web UI needs extra packages: pip install 'dayag[web]'", file=sys.stderr)
        return EXIT_ERROR
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"Warning: listening on {args.host}; anyone who can reach it can submit emails.",
            file=sys.stderr,
        )
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dayag",
        description="Phishing email analyzer: authentication, spoofing, lookalike domains, "
        "malicious links and attachments, IOC export.",
    )
    parser.add_argument("--version", action="version", version=f"dayag {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = commands.add_parser("analyze", help="analyse .eml files")
    analyze_cmd.add_argument(
        "files", nargs="+", metavar="FILE", help=".eml file(s), or - for stdin"
    )
    analyze_cmd.add_argument(
        "-o",
        "--online",
        action="store_true",
        help="enable DNS, RDAP, VirusTotal and AbuseIPDB lookups",
    )
    analyze_cmd.add_argument("--json", action="store_true", help="print the report as JSON")
    analyze_cmd.add_argument("--html", metavar="PATH", help="write a standalone HTML report")
    analyze_cmd.add_argument("--iocs", metavar="PATH", help="write indicators to a file")
    analyze_cmd.add_argument(
        "--ioc-format",
        choices=sorted(IOC_EXPORTERS),
        help="indicator format (default: from the file extension, else csv)",
    )
    analyze_cmd.add_argument(
        "--no-unwrap",
        action="store_true",
        help="analyse a reported-phish wrapper itself, not its attachment",
    )
    analyze_cmd.add_argument(
        "--fail-on",
        choices=[v.value for v in Verdict if v is not Verdict.CLEAN],
        help="exit with status 1 if any verdict is at least this bad",
    )
    analyze_cmd.add_argument(
        "-v", "--verbose", action="store_true", help="show all links and the mail path"
    )
    analyze_cmd.set_defaults(func=cmd_analyze)

    samples_cmd = commands.add_parser("samples", help="list and analyse the bundled samples")
    samples_cmd.set_defaults(func=cmd_samples)

    rules_cmd = commands.add_parser("rules", help="list the detection rules")
    rules_cmd.add_argument("--markdown", action="store_true", help="print docs/DETECTIONS.md")
    rules_cmd.set_defaults(func=cmd_rules)

    serve_cmd = commands.add_parser("serve", help="start the web UI")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8000)
    serve_cmd.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze" and len(args.files) > 1 and (args.html or args.iocs):
        parser.error("--html and --iocs take a single input file")
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
