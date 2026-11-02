from __future__ import annotations

import csv
import io
import json

from conftest import run

from dayag.iocs import iocs_to_csv, iocs_to_json, iocs_to_stix
from dayag.model import Verdict, hit
from dayag.scoring import merge_findings, score, verdict_for


def test_verdict_thresholds() -> None:
    assert verdict_for(0) is Verdict.CLEAN
    assert verdict_for(14) is Verdict.CLEAN
    assert verdict_for(15) is Verdict.SUSPICIOUS
    assert verdict_for(40) is Verdict.LIKELY_PHISHING
    assert verdict_for(70) is Verdict.MALICIOUS


def test_merge_combines_evidence_and_details() -> None:
    merged = merge_findings(
        [
            hit("LINK-IP", "First.", ["a"]),
            hit("LINK-IP", "Second.", ["b", "a"]),
            hit("CONTENT-URGENCY", "Hurry.", []),
        ]
    )
    assert [f.rule.id for f in merged] == ["LINK-IP", "CONTENT-URGENCY"]  # most severe first
    assert merged[0].detail == "First. Second."
    assert merged[0].evidence == ("a", "b")


def test_score_is_clamped() -> None:
    assert score([hit("AUTH-DMARC-PASS", "x")]) == 0
    many = [hit(rule, "x") for rule in ("ATT-EXECUTABLE", "ATT-RTLO", "ATT-DOUBLE-EXT")]
    assert score(many) == 100


def test_benign_infrastructure_is_never_flagged(sample_bytes) -> None:
    report = run(sample_bytes("04-ceo-fraud.eml"))
    flagged = {i.value for i in report.iocs if i.flagged}
    assert "y.mizrahi.office@gmail.com" in flagged
    assert not any(
        i.type == "domain" and i.value in ("gmail.com", "outlook.com") for i in report.iocs
    )
    # The Microsoft server that relayed the BEC email is not an attacker IP.
    assert "40.92.58.101" not in flagged


def test_shared_services_are_not_domain_indicators(sample_bytes) -> None:
    report = run(sample_bytes("05-israel-post-customs.eml"))
    assert not any(i.type == "domain" and i.value == "bit.ly" for i in report.iocs)
    assert any(i.type == "url" and "bit.ly" in i.value and i.flagged for i in report.iocs)
    assert any(i.type == "ipv4" and i.value == "198.51.100.23" for i in report.iocs)


def test_csv_export_is_defanged(sample_bytes) -> None:
    report = run(sample_bytes("02-paypal-homoglyph.eml"))
    rows = list(csv.DictReader(io.StringIO(iocs_to_csv(report))))
    urls = [r["value"] for r in rows if r["type"] == "url"]
    assert urls and all(u.startswith("hxxp") for u in urls)
    assert all("[.]" in r["value"] for r in rows if r["type"] == "domain")


def test_json_export(sample_bytes) -> None:
    report = run(sample_bytes("03-html-smuggling-invoice.eml"))
    data = json.loads(iocs_to_json(report))
    assert any(i["type"] == "sha256" and i["flagged"] for i in data)


def test_stix_bundle(sample_bytes) -> None:
    report = run(sample_bytes("02-paypal-homoglyph.eml"))
    bundle = json.loads(iocs_to_stix(report))
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    indicators = bundle["objects"]
    assert indicators and all(o["type"] == "indicator" for o in indicators)
    assert all(o["spec_version"] == "2.1" and o["pattern_type"] == "stix" for o in indicators)
    patterns = {o["pattern"] for o in indicators}
    assert "[domain-name:value = 'paypal-resolution-center.com']" in patterns
    # Deterministic ids: the same email gives the same bundle.
    assert iocs_to_stix(report) == iocs_to_stix(
        run(sample_bytes("02-paypal-homoglyph.eml"), now=report.analyzed_at)
    )


def test_report_json_round_trip(sample_bytes) -> None:
    report = run(sample_bytes("07-dhl-shipping-documents.eml"))
    data = json.loads(json.dumps(report.to_dict()))
    assert data["verdict"] == "malicious"
    assert data["findings"][0]["severity"] in ("critical", "high")
    assert data["attachments"][0]["sha256"]
