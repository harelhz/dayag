"""Turn findings into a score and a verdict."""

from __future__ import annotations

from .model import Finding, Verdict

THRESHOLDS = ((70, Verdict.MALICIOUS), (40, Verdict.LIKELY_PHISHING), (15, Verdict.SUSPICIOUS))


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """One finding per rule, combining details and evidence, most severe first.

    Ten shortened links are one indicator, not ten, so each rule is counted
    once in the score however often it fires.
    """
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.rule.id)
        if existing is None:
            merged[finding.rule.id] = finding
            continue
        details = existing.detail
        if finding.detail not in details:
            details = f"{details} {finding.detail}"
        evidence = existing.evidence + tuple(
            e for e in finding.evidence if e not in existing.evidence
        )
        merged[finding.rule.id] = Finding(existing.rule, details, evidence)
    return sorted(merged.values(), key=lambda f: (-f.rule.severity, -f.rule.points, f.rule.id))


def score(findings: list[Finding]) -> int:
    return max(0, min(100, sum(f.rule.points for f in merge_findings(findings))))


def verdict_for(value: int) -> Verdict:
    for threshold, verdict in THRESHOLDS:
        if value >= threshold:
            return verdict
    return Verdict.CLEAN
