"""Find URLs in text, unwrap security-gateway rewrites, build Link records."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlsplit

from .domains import normalize_host, registrable_domain
from .model import Link

MAX_LINKS = 500

_URL = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]+""")
_TRAILING = ".,;:!?)'\"»”’>"
_SCRIPT_SCHEMES = ("javascript:", "data:", "vbscript:")
_IGNORED_SCHEMES = ("mailto:", "tel:", "sms:", "cid:", "#", "about:")


def find_urls(text: str, limit: int = MAX_LINKS) -> list[str]:
    found: list[str] = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(_TRAILING)
        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in found:
            found.append(url)
            if len(found) >= limit:
                break
    return found


def _query_param(url: str, *names: str) -> str:
    params = parse_qs(urlsplit(url).query)
    for name in names:
        if params.get(name):
            return params[name][0]
    return ""


def unwrap(url: str) -> tuple[str, str]:
    """Undo link rewriting by email security gateways.

    Returns (real URL, name of the wrapper) or (url, "") if not wrapped.
    Analysts need the real destination, not safelinks.protection.outlook.com.
    """
    wrapper = ""
    for _ in range(3):  # wrappers are sometimes nested
        try:
            parts = urlsplit(url)
        except ValueError:
            break
        host = (parts.hostname or "").lower()
        inner = ""
        name = ""
        if host.endswith("safelinks.protection.outlook.com"):
            inner, name = _query_param(url, "url"), "Microsoft Safe Links"
        elif host == "urldefense.proofpoint.com" and parts.path.startswith("/v2/url"):
            encoded = _query_param(url, "u")
            inner = unquote(encoded.replace("-", "%").replace("_", "/")) if encoded else ""
            name = "Proofpoint URL Defense"
        elif host == "urldefense.com" and parts.path.startswith("/v3/__"):
            match = re.search(r"/v3/__(.+?)__;", url)
            inner, name = (match.group(1) if match else ""), "Proofpoint URL Defense"
        elif host in ("www.google.com", "google.com") and parts.path == "/url":
            inner, name = _query_param(url, "q", "url"), "Google redirect"
        elif host == "linkprotect.cudasvc.com":
            inner, name = _query_param(url, "a"), "Barracuda Link Protection"
        if not inner or not re.match(r"(?i)https?://", inner):
            break
        url, wrapper = inner, wrapper or name
    return url, wrapper


def make_link(raw_url: str, text: str = "", source: str = "html") -> Link | None:
    """Build a Link from an href or a URL found in text, or None if not web."""
    raw_url = raw_url.strip()
    lowered = raw_url.lower()
    if not raw_url or lowered.startswith(_IGNORED_SCHEMES):
        return None
    if lowered.startswith(_SCRIPT_SCHEMES):
        return Link(url=raw_url[:2048], host="", domain="", text=text, source=source)
    if lowered.startswith("//"):
        raw_url = "https:" + raw_url
    elif lowered.startswith("www."):
        raw_url = "http://" + raw_url
    elif not re.match(r"(?i)[a-z][a-z0-9+.-]*://", raw_url):
        return None  # relative link: no destination to judge
    url, wrapper = unwrap(raw_url)
    try:
        host = normalize_host(urlsplit(url).hostname or "")
    except ValueError:
        host = ""
    if not host:
        return None
    return Link(
        url=url,
        host=host,
        domain=registrable_domain(host),
        text=text,
        source=source,
        wrapped_by=wrapper,
        original=raw_url if wrapper else "",
    )
