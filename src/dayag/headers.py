"""Parse Received chains and authentication results."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime

from .model import AuthSummary, Hop

# --- Received ---------------------------------------------------------------

_FROM = re.compile(r"^\s*from\s+(\S+)(?:\s+\(([^)]*)\))?", re.IGNORECASE)
_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+([A-Za-z0-9-]+)", re.IGNORECASE)
_BRACKETED_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_COMMENT = re.compile(r"\([^()]*\)")
_BARE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

# Ranges that never appear on the public internet. Documentation ranges
# (192.0.2.0/24 and friends) are deliberately not listed so the bundled
# samples behave like real mail.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
        "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
    )
)  # fmt: skip


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in _INTERNAL_NETS)


def _first_ip(text: str) -> str:
    for candidate in [*_BRACKETED_IP.findall(text), *_BARE_IPV4.findall(text)]:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ""


def _parse_date(value: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo else None


def _strip_comments(text: str) -> str:
    for _ in range(3):  # comments can nest
        text = _COMMENT.sub(" ", text)
    return text


def parse_received(values: list[str]) -> list[Hop]:
    """Received headers, top (newest) first, as hops in the order they happened."""
    hops: list[Hop] = []
    previous: datetime | None = None
    for number, value in enumerate(reversed(values), start=1):
        clauses, _, date_text = value.rpartition(";")
        if not clauses:
            clauses, date_text = value, ""
        from_match = _FROM.search(clauses)
        from_section = from_match.group(0) if from_match else ""
        ip = _first_ip(from_section)
        timestamp = _parse_date(date_text)
        delay = None
        if timestamp and previous:
            delay = (timestamp - previous).total_seconds()
        if timestamp:
            previous = timestamp
        uncommented = _strip_comments(clauses)
        by_match = _BY.search(uncommented)
        with_match = _WITH.search(uncommented)
        hops.append(
            Hop(
                number=number,
                from_host=from_match.group(1) if from_match else "",
                by_host=by_match.group(1).rstrip(";") if by_match else "",
                ip=ip,
                internal=is_internal_ip(ip) if ip else False,
                protocol=with_match.group(1).upper() if with_match else "",
                timestamp=timestamp,
                delay=delay,
            )
        )
    return hops


def originating_ips(hops: list[Hop]) -> list[str]:
    """Public IPs in the chain, earliest first. The first is the likely sender.

    Received headers below the receiving organisation's own servers can be
    forged by the sender, so this is a lead, not proof.
    """
    seen: list[str] = []
    for hop in hops:
        if hop.ip and not hop.internal and hop.ip not in seen:
            seen.append(hop.ip)
    return seen


# --- Authentication-Results (RFC 8601) --------------------------------------

_METHOD = re.compile(r"^\s*([a-z][a-z0-9_-]*)\s*=\s*([a-z]+)", re.IGNORECASE)
_PROPERTY = re.compile(
    r"\b(smtp|header|policy|body)\.([a-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^\s;()]+)", re.IGNORECASE
)


@dataclass
class MethodResult:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    comment: str = ""


@dataclass
class AuthHeader:
    authserv_id: str
    results: list[MethodResult]


def parse_authentication_results(value: str) -> AuthHeader:
    clauses = value.split(";")
    authserv_id = ""
    results = []
    for index, clause in enumerate(clauses):
        comments = " ".join(_COMMENT.findall(clause))
        bare = _strip_comments(clause)
        match = _METHOD.match(bare)
        if not match:
            if index == 0:
                authserv_id = bare.split()[0].lower() if bare.split() else ""
            continue
        properties = {
            f"{ptype.lower()}.{prop.lower()}": val.strip('"')
            for ptype, prop, val in _PROPERTY.findall(bare)
        }
        results.append(
            MethodResult(match.group(1).lower(), match.group(2).lower(), properties, comments)
        )
    return AuthHeader(authserv_id, results)


def _domain_of(value: str) -> str:
    return value.rpartition("@")[2].strip("<>").lower()


_RESULT_RANK = {
    "pass": 0,
    "fail": 1,
    "softfail": 2,
    "neutral": 3,
    "temperror": 4,
    "permerror": 5,
    "policy": 6,
    "none": 7,
}


# Methods the summary is built from. A lower header claiming one of these passed is
# flagged even when the receiving server gave no verdict for it.
_SUMMARY_METHODS = ("spf", "dkim", "dmarc", "compauth")


def received_spf_above_auth(header_names: list[str]) -> bool:
    """Whether the receiving server wrote Received-SPF but no Authentication-Results.

    True when the topmost Received-SPF sits above every Authentication-Results
    header with a Received header in between: those Authentication-Results
    were already in the message when it reached the server that checked SPF,
    so the sender may have written them.
    """
    names = [n.lower() for n in header_names]
    if "received-spf" not in names or "authentication-results" not in names:
        return False
    spf = names.index("received-spf")
    auth = names.index("authentication-results")
    return spf < auth and "received" in names[spf + 1 : auth]


def summarise_auth(
    auth_results: list[str],
    arc_results: list[str],
    received_spf: list[str],
    *,
    trusted_authserv: tuple[str, ...] = (),
    received_spf_first: bool = False,
) -> AuthSummary:
    """Combine authentication headers into one verdict per method.

    Only the receiving server's Authentication-Results are trusted: the topmost
    header, plus any directly below it with the same authserv-id. Anything
    lower could have been written by the sender. A topmost header with no
    results ("mx.example; none") means no verdict, not "trust the next one".

    trusted_authserv names the receiving servers' authserv-ids. When given,
    the first block of headers from those servers is trusted instead, wherever
    it sits. received_spf_first (see received_spf_above_auth) means the
    receiving server wrote no Authentication-Results at all.
    """
    summary = AuthSummary()
    headers = [parse_authentication_results(v) for v in auth_results]
    if not headers and arc_results:
        # Forwarded mail: fall back to the newest ARC seal's results.
        arc = sorted(arc_results, key=lambda v: _arc_instance(v), reverse=True)[0]
        headers = [parse_authentication_results(re.sub(r"^\s*i=\d+\s*;", "", arc))]

    trusted_ids = {t.lower() for t in trusted_authserv if t}
    start: int | None = None
    if trusted_ids:
        start = next((i for i, h in enumerate(headers) if h.authserv_id in trusted_ids), None)
    elif headers and not received_spf_first:
        start = 0

    trusted: list[AuthHeader] = []
    untrusted = list(headers)
    if start is not None:
        top = headers[start]
        end = start + 1
        while end < len(headers) and _same_server(top, headers[end], trusted_ids):
            end += 1
        trusted = headers[start:end]
        untrusted = headers[:start] + headers[end:]
        summary.source = top.authserv_id or "receiving server"

    methods: dict[str, list[MethodResult]] = {}
    for header in trusted:
        for result in header.results:
            methods.setdefault(result.method, []).append(result)

    if spf := methods.get("spf"):
        summary.spf = spf[0].result
        summary.spf_domain = _domain_of(spf[0].properties.get("smtp.mailfrom", ""))
    elif received_spf:
        word = received_spf[0].split()[0].lower() if received_spf[0].split() else ""
        summary.spf = word
        summary.source = summary.source or "Received-SPF"
        match = re.search(r"envelope-from=\"?<?([^\s\";>]+)", received_spf[0], re.IGNORECASE)
        summary.spf_domain = _domain_of(match.group(1)) if match else ""

    if dkim := methods.get("dkim"):
        best = min(dkim, key=lambda r: _RESULT_RANK.get(r.result, 9))
        summary.dkim = best.result
        summary.dkim_domains = sorted(
            {
                d.lower()
                for r in dkim
                if r.result == "pass"
                for d in [
                    r.properties.get("header.d") or _domain_of(r.properties.get("header.i", ""))
                ]
                if d
            }
        )

    if dmarc := methods.get("dmarc"):
        summary.dmarc = dmarc[0].result
        summary.dmarc_domain = dmarc[0].properties.get("header.from", "").lower()
        policy = re.search(r"\bp=(\w+)", dmarc[0].comment, re.IGNORECASE)
        summary.dmarc_policy = policy.group(1).lower() if policy else ""

    if compauth := methods.get("compauth"):
        summary.compauth = compauth[0].result

    reported = {m: r[0].result for m, r in methods.items()}
    reported.update({m: getattr(summary, m) for m in _SUMMARY_METHODS if getattr(summary, m)})
    for header in untrusted:
        for result in header.results:
            verdict = reported.get(result.method)
            if result.result != "pass" or verdict == "pass":
                continue
            claimed = f"{result.method}=pass claimed by '{header.authserv_id or 'unknown'}'"
            if verdict:
                summary.contradictions.append(
                    f"{claimed}, receiving server reported {result.method}={verdict}"
                )
            elif result.method in _SUMMARY_METHODS:
                summary.contradictions.append(f"{claimed}, not verified by the receiving server")
    return summary


def _same_server(top: AuthHeader, header: AuthHeader, trusted_ids: set[str]) -> bool:
    if trusted_ids:
        return header.authserv_id in trusted_ids
    return bool(top.authserv_id) and header.authserv_id == top.authserv_id


def _arc_instance(value: str) -> int:
    match = re.match(r"\s*i=(\d+)", value)
    return int(match.group(1)) if match else 0
