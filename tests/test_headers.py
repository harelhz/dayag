from __future__ import annotations

from conftest import build_email, ids, run

from dayag.headers import (
    is_internal_ip,
    originating_ips,
    parse_authentication_results,
    parse_received,
    summarise_auth,
)

GOOGLE_AR = (
    "mx.google.com; dkim=pass header.i=@contoso.com header.s=s1 header.b=abc; "
    "spf=pass (google.com: domain of a@contoso.com designates 1.2.3.4 as permitted sender) "
    "smtp.mailfrom=a@contoso.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=contoso.com"
)
MICROSOFT_AR = (
    "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.example; dkim=none (message not "
    "signed) header.d=none;dmarc=fail action=quarantine header.from=contoso.com;compauth=fail "
    "reason=000"
)


def test_parse_google_style() -> None:
    header = parse_authentication_results(GOOGLE_AR)
    assert header.authserv_id == "mx.google.com"
    methods = {r.method: r for r in header.results}
    assert methods["spf"].properties["smtp.mailfrom"] == "a@contoso.com"
    assert methods["dkim"].properties["header.i"] == "@contoso.com"
    assert "p=REJECT" in methods["dmarc"].comment


def test_parse_microsoft_style_without_authserv_id() -> None:
    summary = summarise_auth([MICROSOFT_AR], [], [])
    assert (summary.spf, summary.dkim, summary.dmarc, summary.compauth) == (
        "fail",
        "none",
        "fail",
        "fail",
    )
    assert summary.spf_domain == "evil.example"
    assert summary.dmarc_domain == "contoso.com"


def test_summary_uses_dkim_domain_and_policy() -> None:
    summary = summarise_auth([GOOGLE_AR], [], [])
    assert summary.source == "mx.google.com"
    assert summary.dkim_domains == ["contoso.com"]
    assert summary.dmarc_policy == "reject"


def test_lower_header_cannot_override_the_receiving_server() -> None:
    forged = (
        "attacker.example; spf=pass smtp.mailfrom=contoso.com; dmarc=pass header.from=contoso.com"
    )
    summary = summarise_auth([MICROSOFT_AR.replace("spf=fail", "spf=fail"), forged], [], [])
    assert summary.dmarc == "fail"
    assert any("dmarc=pass claimed" in c for c in summary.contradictions)


def test_arc_results_used_when_no_authentication_results() -> None:
    arc = "i=1; mx.example.net; spf=softfail smtp.mailfrom=a.example; dmarc=fail header.from=a.example"
    summary = summarise_auth([], [arc], [])
    assert summary.spf == "softfail"
    assert summary.dmarc == "fail"


def test_received_spf_fallback() -> None:
    summary = summarise_auth([], [], ["Fail (domain of x@evil.example does not designate ...)"])
    assert summary.spf == "fail"


def test_received_chain_is_chronological() -> None:
    hops = parse_received(
        [
            "from mail.relay.example (mail.relay.example [198.51.100.20]) by mx.contoso.com with ESMTPS "
            "id 1; Mon, 02 Nov 2026 10:00:10 +0000",
            "by sender.example (Postfix, from userid 33) id 2; Mon, 02 Nov 2026 10:00:00 +0000",
        ]
    )
    assert [h.number for h in hops] == [1, 2]
    assert hops[0].from_host == ""  # "from userid" inside a comment is not a sender
    assert hops[0].by_host == "sender.example"
    assert hops[1].ip == "198.51.100.20"
    assert hops[1].delay == 10
    assert hops[1].protocol == "ESMTPS"


def test_internal_ips_are_skipped_for_origin() -> None:
    hops = parse_received(
        [
            "from edge (edge [203.0.113.5]) by mx; Mon, 02 Nov 2026 10:00:10 +0000",
            "from laptop ([10.0.0.12]) by edge; Mon, 02 Nov 2026 10:00:00 +0000",
        ]
    )
    assert originating_ips(hops) == ["203.0.113.5"]
    assert is_internal_ip("192.168.1.1") and is_internal_ip("fe80::1")
    assert not is_internal_ip("8.8.8.8")


def test_dmarc_failure_findings() -> None:
    report = run(build_email({"Authentication-Results": MICROSOFT_AR}))
    assert {"AUTH-SPF-FAIL", "AUTH-DKIM-NONE", "AUTH-DMARC-FAIL", "AUTH-COMPAUTH-FAIL"} <= ids(
        report
    )


def test_missing_authentication_is_informational() -> None:
    report = run(build_email())
    assert "AUTH-MISSING" in ids(report)
    assert report.score == 0


def test_unaligned_dkim_is_noted() -> None:
    ar = "mx.contoso.com; dkim=pass header.d=sendgrid.net; spf=pass smtp.mailfrom=bounce.sendgrid.net"
    report = run(build_email({"Authentication-Results": ar}))
    assert "AUTH-DKIM-UNALIGNED" in ids(report)
