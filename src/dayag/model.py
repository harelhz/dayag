"""Data structures shared by the parser, the checks and the renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .rules import Rule, Severity, get_rule


@dataclass(frozen=True)
class Finding:
    rule: Rule
    detail: str
    evidence: tuple[str, ...] = ()

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule.id,
            "title": self.rule.title,
            "category": self.rule.category.value,
            "severity": self.rule.severity.label,
            "points": self.rule.points,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "attack": list(self.rule.attack),
        }


def hit(rule_id: str, detail: str, evidence: tuple[str, ...] | list[str] = ()) -> Finding:
    """Create a finding for a rule from the registry."""
    return Finding(get_rule(rule_id), detail, tuple(evidence))


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    MALICIOUS = "malicious"

    @property
    def label(self) -> str:
        return _VERDICT_LABELS[self]

    @property
    def rank(self) -> int:
        return list(Verdict).index(self)


_VERDICT_LABELS = {
    Verdict.CLEAN: "No strong indicators",
    Verdict.SUSPICIOUS: "Suspicious",
    Verdict.LIKELY_PHISHING: "Likely phishing",
    Verdict.MALICIOUS: "Malicious",
}


@dataclass(frozen=True)
class Address:
    name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower() if "@" in self.address else ""

    def __str__(self) -> str:
        return f'"{self.name}" <{self.address}>' if self.name else self.address


@dataclass
class Link:
    url: str
    host: str
    domain: str
    text: str = ""
    source: str = "html"
    wrapped_by: str = ""
    original: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    kind: str
    inline: bool = False
    archive_members: list[str] = field(default_factory=list)
    archive_encrypted: bool = False
    macros: bool = False
    remote_content: str = ""
    pdf_traits: list[str] = field(default_factory=list)
    html_traits: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Hop:
    number: int
    from_host: str
    by_host: str
    ip: str
    internal: bool
    protocol: str
    timestamp: datetime | None
    delay: float | None


@dataclass
class AuthSummary:
    source: str = ""
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    compauth: str = ""
    spf_domain: str = ""
    dkim_domains: list[str] = field(default_factory=list)
    dmarc_domain: str = ""
    dmarc_policy: str = ""
    contradictions: list[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.spf or self.dkim or self.dmarc or self.compauth)


@dataclass(frozen=True)
class LookupResult:
    source: str
    target: str
    status: str  # "ok", "not found", "error" or "skipped"
    summary: str


@dataclass(frozen=True)
class Ioc:
    type: str  # email, domain, url, ipv4, ipv6, sha256, md5
    value: str
    context: str
    flagged: bool


@dataclass
class EmailSummary:
    subject: str
    sender: str
    to: str
    cc: str
    date: str
    message_id: str
    reply_to: str
    return_path: str
    size: int


@dataclass
class Report:
    tool_version: str
    analyzed_at: datetime
    verdict: Verdict
    score: int
    summary: EmailSummary
    findings: list[Finding]
    auth: AuthSummary
    links: list[Link]
    attachments: list[AttachmentInfo]
    hops: list[Hop]
    iocs: list[Ioc]
    lookups: list[LookupResult]
    body_preview: str
    reported_wrapper: str = ""
    online: bool = False
    duration_ms: int = 0

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "dayag", "version": self.tool_version},
            "analyzed_at": self.analyzed_at.isoformat(),
            "verdict": self.verdict.value,
            "verdict_label": self.verdict.label,
            "score": self.score,
            "online": self.online,
            "reported_wrapper": self.reported_wrapper or None,
            "email": asdict(self.summary),
            "findings": [f.to_dict() for f in self.findings],
            "authentication": asdict(self.auth),
            "links": [asdict(link) for link in self.links],
            "attachments": [asdict(a) for a in self.attachments],
            "hops": [
                {
                    **asdict(h),
                    "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                }
                for h in self.hops
            ],
            "iocs": [asdict(i) for i in self.iocs],
            "lookups": [asdict(lookup) for lookup in self.lookups],
            "duration_ms": self.duration_ms,
        }
