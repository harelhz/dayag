"""Online lookups, with every network call mocked."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import ids, run

from dayag.config import Config
from dayag.enrich import dnscheck

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
KEYS = Config(virustotal_key="vt-test", abuseipdb_key="abuse-test")


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnscheck, "txt_records", lambda name: [])
    monkeypatch.setattr(dnscheck, "has_mail_server", lambda domain: False)


def rdap(date: str) -> httpx.Response:
    return httpx.Response(
        200, json={"events": [{"eventAction": "registration", "eventDate": date}]}
    )


@respx.mock(assert_all_mocked=True)
def test_new_domains_and_dns(respx_mock: respx.MockRouter, sample_bytes) -> None:
    respx_mock.get(url__regex=r"https://rdap\.org/domain/.*").mock(
        return_value=rdap("2026-10-25T08:00:00Z")
    )
    report = run(
        sample_bytes("07-dhl-shipping-documents.eml"), online=True, config=Config(), now=NOW
    )
    assert {"SENDER-NEW-DOMAIN", "SENDER-NO-DMARC", "SENDER-NO-MX"} <= ids(report)
    rdap_results = [r for r in report.lookups if r.source == "RDAP"]
    assert rdap_results and "8 days ago" in rdap_results[0].summary
    # Without API keys the paid lookups are skipped, not failed.
    assert any(r.source == "VirusTotal" and r.status == "skipped" for r in report.lookups)


@respx.mock(assert_all_mocked=True)
def test_old_domain_is_not_flagged(respx_mock: respx.MockRouter, sample_bytes) -> None:
    respx_mock.get(url__regex=r"https://rdap\.org/.*").mock(
        return_value=rdap("2009-01-01T00:00:00Z")
    )
    report = run(
        sample_bytes("07-dhl-shipping-documents.eml"), online=True, config=Config(), now=NOW
    )
    assert "SENDER-NEW-DOMAIN" not in ids(report)


@respx.mock(assert_all_mocked=True, assert_all_called=False)
def test_virustotal_and_abuseipdb(respx_mock: respx.MockRouter, sample_bytes) -> None:
    respx_mock.get(url__regex=r"https://rdap\.org/.*").mock(return_value=httpx.Response(404))
    vt = respx_mock.get(url__startswith="https://www.virustotal.com/api/v3/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 12,
                            "suspicious": 1,
                            "harmless": 0,
                            "undetected": 60,
                        }
                    }
                }
            },
        )
    )
    abuse = respx_mock.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 87, "totalReports": 41, "countryCode": "NL"}},
        )
    )
    report = run(sample_bytes("03-html-smuggling-invoice.eml"), online=True, config=KEYS, now=NOW)
    assert {"ATT-REPUTATION"} <= ids(report)
    # Read-only: only GET requests, the API key in a header, never in the URL.
    for call in vt.calls:
        assert call.request.method == "GET"
        assert call.request.headers["x-apikey"] == "vt-test"
        assert "vt-test" not in str(call.request.url)
    assert vt.call_count <= KEYS.max_virustotal_lookups
    # The sender here is Gmail's infrastructure, so it is checked but reported, not hidden.
    assert abuse.called


@respx.mock(assert_all_mocked=True, assert_all_called=False)
def test_abuseipdb_flags_reported_ip(respx_mock: respx.MockRouter, sample_bytes) -> None:
    respx_mock.get(url__regex=r"https://rdap\.org/.*").mock(return_value=httpx.Response(404))
    respx_mock.get(url__startswith="https://www.virustotal.com/").mock(
        return_value=httpx.Response(404)
    )
    respx_mock.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 87, "totalReports": 41}}
        )
    )
    report = run(sample_bytes("05-israel-post-customs.eml"), online=True, config=KEYS, now=NOW)
    assert "INFRA-IP-REPUTATION" in ids(report)


@respx.mock(assert_all_mocked=True)
def test_network_errors_are_reported_not_raised(respx_mock: respx.MockRouter, sample_bytes) -> None:
    respx_mock.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("offline"))
    report = run(sample_bytes("02-paypal-homoglyph.eml"), online=True, config=KEYS, now=NOW)
    assert "META-LOOKUP-FAILED" in ids(report)
    assert report.verdict.value == "malicious"  # offline findings still stand


def test_offline_by_default_makes_no_requests(sample_bytes) -> None:
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route()  # would catch any request
        report = run(sample_bytes("02-paypal-homoglyph.eml"))
    assert not route.called
    assert report.lookups == []
