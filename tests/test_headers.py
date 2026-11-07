from __future__ import annotations

import pytest
from conftest import build_email, ids, run

from dayag.config import Config
from dayag.headers import (
    is_internal_ip,
    originating_ips,
    parse_authentication_results,
    parse_received,
    received_spf_above_auth,
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


RECEIVER_NONE = "mx.victim-corp.example; none"
RECEIVER_FAIL = (
    "mx.victim-corp.example; spf=fail smtp.mailfrom=paypal.com; dkim=none; "
    "dmarc=fail (p=REJECT) header.from=paypal.com"
)
FORGED_PAYPAL = (
    "mail.attacker.example; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; "
    "dmarc=pass header.from=paypal.com"
)
PAYPAL_PHISH = {
    "From": "PayPal <service@paypal.com>",
    "Subject": "Your account has been limited",
}


def test_receiving_header_without_results_is_no_verdict() -> None:
    summary = summarise_auth([RECEIVER_NONE, FORGED_PAYPAL], [], [])
    assert summary.source == "mx.victim-corp.example"
    assert (summary.spf, summary.dkim, summary.dmarc, summary.dkim_domains) == ("", "", "", [])
    assert len(summary.contradictions) == 3
    assert all("not verified by the receiving server" in c for c in summary.contradictions)


def test_forged_header_below_empty_receiving_header_is_flagged() -> None:
    report = run(
        build_email({**PAYPAL_PHISH, "Authentication-Results": [RECEIVER_NONE, FORGED_PAYPAL]})
    )
    assert {"AUTH-MISSING", "AUTH-FORGED-RESULTS"} <= ids(report)
    assert "AUTH-DMARC-PASS" not in ids(report)
    assert report.auth.dmarc == ""


def test_lower_header_copying_the_receivers_id_is_not_trusted() -> None:
    copied = FORGED_PAYPAL.replace("mail.attacker.example", "mx.victim-corp.example")
    summary = summarise_auth([RECEIVER_FAIL, GOOGLE_AR, copied], [], [])
    assert (summary.spf, summary.dkim, summary.dmarc) == ("fail", "none", "fail")
    assert summary.dkim_domains == []
    assert any("dkim=pass claimed by 'mx.victim-corp.example'" in c for c in summary.contradictions)


def test_adjacent_headers_from_the_receiving_server_are_combined() -> None:
    # Postfix with separate SPF and DKIM milters adds one header each.
    summary = summarise_auth(
        [
            "mx.contoso.com; dkim=pass header.d=contoso.com",
            "mx.contoso.com; spf=pass smtp.mailfrom=contoso.com",
        ],
        [],
        [],
    )
    assert (summary.spf, summary.dkim, summary.contradictions) == ("pass", "pass", [])


def test_received_spf_beats_authentication_results_written_before_it() -> None:
    report = run(
        build_email(
            {
                **PAYPAL_PHISH,
                "Received-SPF": "Fail (mx.victim-corp.example: domain of paypal.com does not "
                "designate 203.0.113.9 as permitted sender) envelope-from=<service@paypal.com>",
                "Received": "from mail.attacker.example (mail.attacker.example [203.0.113.9]) "
                "by mx.victim-corp.example; Mon, 02 Nov 2026 10:00:10 +0000",
                "Authentication-Results": FORGED_PAYPAL,
            }
        )
    )
    assert (report.auth.spf, report.auth.dmarc, report.auth.source) == ("fail", "", "Received-SPF")
    assert {"AUTH-SPF-FAIL", "AUTH-FORGED-RESULTS"} <= ids(report)
    assert "AUTH-DMARC-PASS" not in ids(report)


def test_received_spf_above_auth_needs_a_hop_in_between() -> None:
    # Gmail writes Received-SPF directly above its own Authentication-Results.
    assert not received_spf_above_auth(["Received", "Received-SPF", "Authentication-Results"])
    assert received_spf_above_auth(["Received-SPF", "Received", "Authentication-Results"])
    assert not received_spf_above_auth(["Authentication-Results", "Received", "Received-SPF"])
    assert not received_spf_above_auth(["Received-SPF", "Received"])


def test_trusted_authserv_ignores_other_servers() -> None:
    trusted = ("mx.victim-corp.example",)
    summary = summarise_auth([FORGED_PAYPAL], [], [], trusted_authserv=trusted)
    assert (summary.spf, summary.dkim, summary.dmarc, summary.source) == ("", "", "", "")
    assert len(summary.contradictions) == 3

    # Headers added above it by internal hops do not hide the receiving server's.
    internal = "relay.internal.example; spf=pass smtp.mailfrom=paypal.com"
    summary = summarise_auth([internal, RECEIVER_FAIL], [], [], trusted_authserv=trusted)
    assert (summary.spf, summary.dmarc) == ("fail", "fail")
    assert summary.source == "mx.victim-corp.example"


def test_trusted_authserv_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAYAG_TRUSTED_AUTHSERV", "MX.Victim-Corp.example, mx2.victim-corp.example")
    assert Config.from_env().trusted_authserv == (
        "mx.victim-corp.example",
        "mx2.victim-corp.example",
    )
    report = run(build_email({**PAYPAL_PHISH, "Authentication-Results": FORGED_PAYPAL}))
    assert {"AUTH-MISSING", "AUTH-FORGED-RESULTS"} <= ids(report)
    assert "AUTH-DMARC-PASS" not in ids(report)


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
