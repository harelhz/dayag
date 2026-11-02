"""Reports must be safe to open even though they contain attacker-controlled text."""

from __future__ import annotations

import io

from conftest import build_email, run
from rich.console import Console

from dayag.render.html import render_html
from dayag.render.terminal import render_terminal

XSS = '<script>alert("x")</script><img src=x onerror=alert(1)>'


def hostile_report():
    raw = build_email(
        {
            "Subject": f"Invoice {XSS} [bold red]markup[/] \x1b[31mred\x1b[0m",
            "From": f'"{XSS}" <a@evil.example>',
        },
        text=f"Body {XSS}",
        html=f'<a href="https://evil.example/{XSS}">{XSS}</a>',
        attachments=[(f"{XSS}.html", XSS.encode(), "text/html")],
    )
    return run(raw)


def test_html_report_escapes_everything() -> None:
    html = render_html(hostile_report())
    assert "<script>alert" not in html
    assert "<img src=x" not in html  # no live tag, only escaped text
    assert "&lt;script&gt;" in html and "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_report_is_self_contained() -> None:
    html = render_html(hostile_report())
    assert "Content-Security-Policy" in html
    assert "<link" not in html and "<script" not in html
    assert 'href="https://evil' not in html  # links are shown as defanged text only


def test_terminal_does_not_interpret_markup_or_escapes() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=200, color_system=None, force_terminal=False)
    render_terminal(hostile_report(), console, verbose=True)
    out = buffer.getvalue()
    assert "[bold red]markup[/]" in out  # printed literally, not styled
    assert "\x1b" not in out  # escape sequences from the email are stripped


def test_sample_renders(sample_bytes) -> None:
    html = render_html(run(sample_bytes("05-israel-post-customs.eml")))
    assert "דואר ישראל" in html
    assert "hxxp://198[.]51[.]100[.]23:8080" in html
