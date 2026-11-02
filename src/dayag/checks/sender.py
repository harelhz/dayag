"""Judge who the email claims to come from and where replies go."""

from __future__ import annotations

import re

from ..context import Context
from ..domains import brand_owning, defang, find_lookalike, is_freemail, registrable_domain
from ..knowledge import BRANDS
from ..model import Address, Finding, hit
from ..text import contains_hebrew

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _alias_pattern(alias: str) -> re.Pattern[str]:
    if contains_hebrew(alias):
        return re.compile(re.escape(alias))
    return re.compile(r"(?<![\w.])" + re.escape(alias) + r"(?![\w])", re.IGNORECASE)


_ALIASES = [(brand, _alias_pattern(alias)) for brand in BRANDS for alias in brand.aliases]


def _lookalike_findings(address: Address, role: str) -> list[Finding]:
    match = find_lookalike(address.domain)
    if not match:
        return []
    rule = "SENDER-LOOKALIKE" if match.strong else "SENDER-COMBOSQUAT"
    return [
        hit(
            rule,
            f"The {role} domain {address.domain} is a {match.describe()}.",
            [defang(address.address)],
        )
    ]


def check_sender(ctx: Context) -> list[Finding]:
    sender = ctx.sender
    if sender is None or not sender.domain:
        return []
    findings = _lookalike_findings(sender, "From")
    from_domain = registrable_domain(sender.domain)
    owner = brand_owning(sender.domain)

    if sender.name:
        embedded = _EMAIL_IN_NAME.search(sender.name)
        if embedded and embedded.group(0).lower() != sender.address.lower():
            findings.append(
                hit(
                    "SENDER-DISPLAY-ADDRESS",
                    f'The display name shows "{embedded.group(0)}" but the email comes from '
                    f"{sender.address}.",
                    [defang(sender.address)],
                )
            )
        for brand, pattern in _ALIASES:
            if brand is not owner and pattern.search(sender.name):
                findings.append(
                    hit(
                        "SENDER-DISPLAY-BRAND",
                        f'The display name "{sender.name}" claims to be {brand.name}, but '
                        f"{sender.domain} does not belong to {brand.name}.",
                        [str(sender)],
                    )
                )
                break

    if is_freemail(sender.domain):
        findings.append(hit("SENDER-FREEMAIL", f"Sent from a free {sender.domain} account."))

    for reply in ctx.reply_to:
        if not reply.domain or reply.address.lower() == sender.address.lower():
            continue
        findings += _lookalike_findings(reply, "Reply-To")
        if is_freemail(reply.domain):
            findings.append(
                hit(
                    "SENDER-REPLYTO-FREEMAIL",
                    f"Replies go to {reply.address} instead of {sender.address}.",
                    [defang(reply.address)],
                )
            )
        elif registrable_domain(reply.domain) != from_domain:
            findings.append(
                hit(
                    "SENDER-REPLYTO-MISMATCH",
                    f"Replies go to {reply.domain}, not {from_domain}.",
                    [defang(reply.address)],
                )
            )

    if ctx.return_path and "@" in ctx.return_path:
        bounce_domain = registrable_domain(ctx.return_path.rpartition("@")[2])
        if bounce_domain != from_domain:
            findings.append(
                hit(
                    "SENDER-RETURNPATH-MISMATCH",
                    f"Bounces go to {bounce_domain}; the From domain is {from_domain}.",
                )
            )
    return findings
