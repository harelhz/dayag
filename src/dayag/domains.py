"""Domain helpers: registrable domains, brand ownership and lookalike detection."""

from __future__ import annotations

import contextlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

import tldextract

from .knowledge import (
    BRANDS,
    FREE_HOSTING,
    FREEMAIL_DOMAINS,
    INFRASTRUCTURE_DOMAINS,
    TYPO_EXCEPTIONS,
    Brand,
)

# The bundled Public Suffix List snapshot, so analysis never touches the
# network. Private suffixes (web.app, github.io...) are included: on those
# platforms the label in front of the suffix belongs to whoever registered it.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def normalize_host(host: str) -> str:
    """Lower-case, strip dots and convert Unicode names to their ASCII (punycode) form."""
    host = host.strip().strip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host.isascii():
        with contextlib.suppress(UnicodeError):
            host = host.encode("idna").decode("ascii")
    return host


@lru_cache(maxsize=8192)
def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, domain label, public suffix) of a normalised host name."""
    result = _EXTRACT(host)
    return result.subdomain, result.domain, result.suffix


def registrable_domain(host: str) -> str:
    """The part of a host name someone registered: login.paypal.co.uk -> paypal.co.uk."""
    host = normalize_host(host)
    _, domain, suffix = split_host(host)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return host


def has_public_suffix(host: str) -> bool:
    return bool(split_host(normalize_host(host))[2])


def to_unicode(host: str) -> str:
    """Decode punycode labels so lookalike characters can be compared."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError):
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Browsers also accept decimal and hex forms: http://3232235777/
        return host.isdigit() or bool(re.fullmatch(r"0x[0-9a-f]+", host))
    return True


def matches_domain(host: str, domains: frozenset[str] | tuple[str, ...]) -> bool:
    """True if host is one of the domains or a subdomain of one."""
    host = normalize_host(host)
    if host in domains:
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in domains for i in range(1, len(parts)))


def brand_owning(host: str) -> Brand | None:
    """The brand a host really belongs to, if any."""
    for brand in BRANDS:
        if matches_domain(host, brand.domains):
            return brand
    return None


def is_freemail(domain: str) -> bool:
    return normalize_host(domain) in FREEMAIL_DOMAINS or registrable_domain(domain) in (
        FREEMAIL_DOMAINS
    )


def is_free_hosting(host: str) -> bool:
    return matches_domain(host, FREE_HOSTING)


def is_known_legit(host: str) -> bool:
    """Brand, free-mail and big-platform domains: not impersonations themselves."""
    return (
        brand_owning(host) is not None
        or is_freemail(host)
        or matches_domain(host, INFRASTRUCTURE_DOMAINS)
    )


# --- Lookalikes -------------------------------------------------------------

# Characters from other scripts that render like Latin letters. NFKD
# normalisation below already handles accented Latin letters (á -> a).
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic
        "а": "a",
        "е": "e",
        "ё": "e",
        "і": "i",
        "ї": "i",
        "ј": "j",
        "к": "k",
        "о": "o",
        "р": "p",
        "с": "c",
        "ѕ": "s",
        "у": "y",
        "х": "x",
        "һ": "h",
        "ԁ": "d",
        "ԛ": "q",
        "ԝ": "w",
        "ӏ": "l",
        "в": "b",
        "м": "m",
        "н": "h",
        "т": "t",
        "п": "n",
        # Greek
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "ϲ": "c",
        # Armenian and others
        "օ": "o",
        "ս": "u",
        "ո": "n",
        "ɡ": "g",
        "ı": "i",
        "ł": "l",
        "ø": "o",
        "đ": "d",
        "ħ": "h",
    }
)
# ASCII characters attackers swap in. Both sides of a comparison go through
# the same folding, so mapping i and l to the same letter is safe.
_ASCII_FOLD = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "4": "a", "5": "s"})
_SEQUENCE_FOLD = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@lru_cache(maxsize=8192)
def skeleton(label: str) -> str:
    """Map a label to what it looks like, so paypal, pаypal and paypa1 compare equal."""
    s = label.lower().translate(_CONFUSABLES)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.translate(_ASCII_FOLD)
    for seq, replacement in _SEQUENCE_FOLD:
        s = s.replace(seq, replacement)
    return s


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: insertions, deletions, substitutions, swaps."""
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


@dataclass(frozen=True)
class Lookalike:
    brand: Brand
    technique: str

    @property
    def strong(self) -> bool:
        """A near-identical copy rather than a domain that merely mentions the brand."""
        return self.technique in _STRONG

    def describe(self) -> str:
        """A noun phrase: 'homoglyph of paypal.com: ...'."""
        legit, name = self.brand.domains[0], self.brand.name
        return {
            "homoglyph": f"homoglyph of {legit}: it uses look-alike letters from another alphabet",
            "character swap": f"lookalike of {legit} with swapped characters",
            "typo": f"typosquat of {legit}",
            "different TLD": f"copy of {legit} under another top-level domain",
            "brand name in domain": f"domain that uses the {name} name without belonging to {name}",
            "brand name in subdomain": (
                f"host that puts the {name} name in a subdomain without belonging to {name}"
            ),
        }[self.technique]


_RANKED = (
    "homoglyph",
    "character swap",
    "typo",
    "different TLD",
    "brand name in domain",
    "brand name in subdomain",
)
_STRONG = frozenset(_RANKED[:4])


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[-_.]+", text) if t]


def _compare(candidate: str, brand_label: str, whole_label: bool) -> str | None:
    """How a domain label (or one hyphen-separated part of it) imitates a brand label."""
    target = skeleton(brand_label)
    if candidate == brand_label:
        return "different TLD" if whole_label else "brand name in domain"
    if skeleton(candidate) == target:
        return "character swap" if candidate.isascii() else "homoglyph"
    # Typos of short brand names collide with real words (apple/apply), so
    # parts of a label are only compared with longer brand names.
    min_length = 5 if whole_label else 6
    shape = skeleton(candidate)
    if (
        len(brand_label) >= min_length
        and candidate not in TYPO_EXCEPTIONS
        # Typosquats keep the first letter: readers notice when it changes.
        and shape[:1] == target[:1]
        and abs(len(shape) - len(target)) <= 2
        and edit_distance(shape, target) <= (2 if len(target) >= 9 else 1)
    ):
        return "typo"
    return None


@lru_cache(maxsize=4096)
def find_lookalike(host: str) -> Lookalike | None:
    """Detect a host imitating a known brand, or None."""
    host = normalize_host(host)
    if not host or is_ip_literal(host):
        return None
    # On free hosting the subdomain/label belongs to whoever signed up, so it
    # is checked even though the platform itself is legitimate.
    if is_known_legit(host) and not is_free_hosting(host):
        return None
    sub, domain, _ = split_host(host)
    if not domain:
        return None
    label = to_unicode(domain)
    parts = _tokens(label)
    sub_parts = [skeleton(t) for t in _tokens(to_unicode(sub))]
    owner = brand_owning(host)

    best: Lookalike | None = None
    for brand in BRANDS:
        if brand is owner:
            continue
        for brand_label in brand.labels:
            target = skeleton(brand_label)
            technique = _compare(label, brand_label, whole_label=True)
            if technique is None and len(parts) > 1:
                # paypal-secure, micros0ft-security: judge each part
                by_part = [t for t in (_compare(p, brand_label, False) for p in parts) if t]
                technique = min(by_part, key=_RANKED.index) if by_part else None
            if technique is None and len(target) >= 6 and target in skeleton(label):
                technique = "brand name in domain"  # mypaypalaccount
            if technique is None and target in sub_parts:
                technique = "brand name in subdomain"
            if technique and (
                best is None or _RANKED.index(technique) < _RANKED.index(best.technique)
            ):
                best = Lookalike(brand, technique)
    return best


# --- Defanging --------------------------------------------------------------


def defang(value: str) -> str:
    """Make a URL, domain, IP or address safe to paste: hxxps://evil[.]example/."""
    value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    if "://" in value:
        scheme, _, rest = value.partition("://")
        netloc, sep, path = rest.partition("/")
        return f"{scheme}://{netloc.replace('.', '[.]')}{sep}{path}"
    return value.replace(".", "[.]").replace("@", "[@]")
