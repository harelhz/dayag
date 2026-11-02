"""Judge how the email was sent."""

from __future__ import annotations

from ..context import Context
from ..knowledge import MAILER_SOFTWARE
from ..model import Finding, hit


def check_infrastructure(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    script = ctx.email.header("X-PHP-Originating-Script")
    if script:
        findings.append(hit("INFRA-PHP-SCRIPT", f"Sent by the PHP script '{script}'.", [script]))
    mailer = ctx.email.header("X-Mailer") or ctx.email.header("User-Agent")
    lowered = mailer.lower()
    if any(name in lowered for name in MAILER_SOFTWARE):
        findings.append(hit("INFRA-MAILER", f"X-Mailer: {mailer}", [mailer]))
    if not ctx.email.header("Message-ID"):
        findings.append(hit("INFRA-NO-MESSAGE-ID", "The email has no Message-ID header."))
    return findings
