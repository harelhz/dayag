"""Judge SPF, DKIM and DMARC as reported by the receiving server."""

from __future__ import annotations

from ..context import Context
from ..domains import registrable_domain
from ..model import Finding, hit


def check_authentication(ctx: Context) -> list[Finding]:
    auth = ctx.auth
    findings: list[Finding] = []
    if not auth.present:
        return [hit("AUTH-MISSING", "The message has no Authentication-Results header.")]
    source = f"according to {auth.source}" if auth.source else ""

    spf_domain = auth.spf_domain or "the envelope sender's domain"
    if auth.spf == "fail":
        findings.append(hit("AUTH-SPF-FAIL", f"SPF failed for {spf_domain} {source}.".strip()))
    elif auth.spf == "softfail":
        findings.append(hit("AUTH-SPF-SOFTFAIL", f"SPF soft-failed for {spf_domain}."))
    elif auth.spf in ("none", "neutral", "temperror", "permerror", "policy"):
        findings.append(hit("AUTH-SPF-NONE", f"SPF result for {spf_domain}: {auth.spf}."))

    if auth.dkim in ("fail", "permerror"):
        findings.append(hit("AUTH-DKIM-FAIL", f"DKIM result: {auth.dkim}."))
    elif auth.dkim in ("none", "neutral", "temperror", "policy"):
        findings.append(hit("AUTH-DKIM-NONE", "The message carries no valid DKIM signature."))
    elif auth.dkim == "pass" and ctx.sender_domain:
        from_domain = registrable_domain(ctx.sender_domain)
        signers = {registrable_domain(d) for d in auth.dkim_domains}
        if signers and from_domain not in signers:
            findings.append(
                hit(
                    "AUTH-DKIM-UNALIGNED",
                    f"Signed by {', '.join(sorted(signers))}, not by {from_domain}.",
                )
            )

    if auth.dmarc == "fail":
        policy = f" The domain's policy is p={auth.dmarc_policy}." if auth.dmarc_policy else ""
        findings.append(
            hit(
                "AUTH-DMARC-FAIL",
                f"DMARC failed for {auth.dmarc_domain or ctx.sender_domain or 'the From domain'}."
                + policy,
            )
        )
    elif auth.dmarc == "none":
        findings.append(
            hit("AUTH-DMARC-NONE", f"{auth.dmarc_domain or ctx.sender_domain} has no DMARC policy.")
        )
    elif auth.dmarc == "pass":
        aligned = (
            not auth.dmarc_domain
            or not ctx.sender_domain
            or (registrable_domain(auth.dmarc_domain) == registrable_domain(ctx.sender_domain))
        )
        if aligned:
            findings.append(
                hit("AUTH-DMARC-PASS", f"The email is authenticated as {ctx.sender_domain}.")
            )

    if auth.compauth == "fail":
        findings.append(hit("AUTH-COMPAUTH-FAIL", "Exchange Online reports compauth=fail."))

    if auth.contradictions:
        findings.append(
            hit(
                "AUTH-FORGED-RESULTS",
                "A lower Authentication-Results header contradicts the receiving server.",
                auth.contradictions,
            )
        )
    return findings
