"""Choose which domains are worth looking up."""

from __future__ import annotations

from ..context import Context
from ..domains import (
    is_free_hosting,
    is_freemail,
    is_ip_literal,
    is_known_legit,
    matches_domain,
    registrable_domain,
)
from ..knowledge import CLICK_TRACKERS, URL_SHORTENERS


def _worth_checking(host: str) -> bool:
    return bool(host) and not (
        is_ip_literal(host)
        or is_known_legit(host)
        or is_freemail(host)
        or is_free_hosting(host)
        or matches_domain(host, CLICK_TRACKERS)
        or matches_domain(host, URL_SHORTENERS)
    )


def domains_to_check(ctx: Context, limit: int) -> list[tuple[str, str]]:
    """(registrable domain, role) pairs: sender first, then flagged links, then other links."""
    candidates: list[tuple[str, str]] = []
    if ctx.sender:
        candidates.append((ctx.sender.domain, "sender"))
    candidates += [(r.domain, "sender") for r in ctx.reply_to]
    links = sorted(ctx.links, key=lambda link: not link.flags)
    candidates += [(link.host, "link") for link in links]

    chosen: dict[str, str] = {}
    for host, role in candidates:
        if not _worth_checking(host):
            continue
        domain = registrable_domain(host)
        if domain not in chosen:
            chosen[domain] = role
        if len(chosen) >= limit:
            break
    return list(chosen.items())
