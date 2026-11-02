"""Render reports as HTML with Jinja2 (autoescaping on)."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files

from jinja2 import Environment, PackageLoader, StrictUndefined

from ..domains import defang
from ..model import Report
from ..text import for_display


def filesize(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024 or unit == "MB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} MB"  # pragma: no cover


def when(moment: datetime | None) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S") if moment else "—"


def delay(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 0:
        return f"{seconds:.0f} s (clock skew)"
    if seconds < 120:
        return f"{seconds:.0f} s"
    if seconds < 7200:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def result_class(result: str) -> str:
    if result == "pass":
        return "res-pass"
    if result in ("fail", "permerror"):
        return "res-fail"
    if not result or result == "none":
        return "res-none"
    return "res-warn"


def show(value: object, limit: int | None = None) -> str:
    return for_display(str(value or ""), limit)


@lru_cache(maxsize=1)
def environment() -> Environment:
    env = Environment(
        loader=PackageLoader("dayag", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    env.filters.update(
        defang=defang,
        filesize=filesize,
        when=when,
        delay=delay,
        result_class=result_class,
        show=show,
    )
    return env


@lru_cache(maxsize=1)
def stylesheet() -> str:
    return files("dayag").joinpath("static/dayag.css").read_text(encoding="utf-8")


def render_html(report: Report) -> str:
    """A single self-contained HTML file: inline CSS, no scripts, no remote resources."""
    return environment().get_template("report.html.j2").render(r=report, css=stylesheet())
