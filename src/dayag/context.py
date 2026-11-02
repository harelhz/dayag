"""Everything extracted from an email, computed once and shared by all checks.

Extraction (facts) is kept apart from the checks (judgements): this module
never decides whether something is suspicious.
"""

from __future__ import annotations

from dataclasses import dataclass

from .filetypes import inspect_attachment
from .headers import parse_received, summarise_auth
from .htmlscan import HtmlScan
from .model import Address, AttachmentInfo, AuthSummary, Hop, Link
from .parsing import ParsedEmail
from .text import for_matching
from .urls import MAX_LINKS, find_urls, make_link


@dataclass
class Context:
    email: ParsedEmail
    sender: Address | None
    reply_to: list[Address]
    return_path: str
    html: HtmlScan
    text: str
    links: list[Link]
    attachments: list[AttachmentInfo]
    hops: list[Hop]
    auth: AuthSummary

    @property
    def sender_domain(self) -> str:
        return self.sender.domain if self.sender else ""


def build_context(email: ParsedEmail) -> Context:
    html = HtmlScan()
    for body in email.html_bodies:
        html.scan(body)
    attachments = [inspect_attachment(a) for a in email.attachments]
    # Prefer a real address: "From: Levi, Alice <a@b>" parses as two entries.
    senders = [a for a in email.addresses("From") if "@" in a.address] or email.addresses("From")
    return_path = email.header("Return-Path").strip().strip("<>").strip()
    text = for_matching(" ".join([email.header("Subject"), *email.text_bodies, html.text]))
    return Context(
        email=email,
        sender=senders[0] if senders else None,
        reply_to=email.addresses("Reply-To"),
        return_path=return_path,
        html=html,
        text=text[:500_000],
        links=_collect_links(email, html, attachments),
        attachments=attachments,
        hops=parse_received(email.headers("Received")),
        auth=summarise_auth(
            email.headers("Authentication-Results"),
            email.headers("ARC-Authentication-Results"),
            email.headers("Received-SPF"),
        ),
    )


def _collect_links(
    email: ParsedEmail, html: HtmlScan, attachments: list[AttachmentInfo]
) -> list[Link]:
    candidates: list[tuple[str, str, str]] = []
    candidates += [(href, text, "html") for href, text in html.anchors]
    candidates += [(action, "", "form") for action in html.forms if action]
    candidates += [(url, "", "html") for url in html.frames + html.refresh_urls]
    for body in email.text_bodies:
        candidates += [(url, "", "text") for url in find_urls(body)]
    for attachment in attachments:
        candidates += [(url, "", f"attachment: {attachment.filename}") for url in attachment.urls]

    links: dict[str, Link] = {}
    for url, text, source in candidates:
        link = make_link(url, text, source)
        if link and link.url not in links:
            links[link.url] = link
            if len(links) >= MAX_LINKS:
                break
    return list(links.values())
