from __future__ import annotations

import json
from pathlib import Path

import pytest

from dayag.cli import main
from dayag.demo import get_sample
from dayag.rules import detections_markdown


def sample_path(name: str) -> str:
    sample = get_sample(name)
    assert sample is not None
    return str(sample.path)


def test_analyze_prints_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", sample_path("02-paypal-homoglyph.eml")]) == 0
    out = capsys.readouterr().out
    assert "MALICIOUS" in out and "LINK-LOOKALIKE" in out


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    main(["analyze", "--json", sample_path("04-ceo-fraud.eml")])
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "likely_phishing"


def test_multiple_files_and_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    files = [sample_path("01-github-notification.eml"), sample_path("04-ceo-fraud.eml")]
    assert main(["analyze", *files, "--fail-on", "malicious"]) == 0
    assert main(["analyze", *files, "--fail-on", "likely_phishing"]) == 1
    assert "Summary" in capsys.readouterr().out


def test_exports(tmp_path: Path) -> None:
    html, iocs, stix = tmp_path / "r.html", tmp_path / "i.csv", tmp_path / "s.json"
    source = sample_path("06-reported-m365-phish.eml")
    assert main(["analyze", source, "--html", str(html), "--iocs", str(iocs)]) == 0
    assert main(["analyze", source, "--iocs", str(stix), "--ioc-format", "stix"]) == 0
    assert "Malicious" in html.read_text()
    assert iocs.read_text().startswith("type,value,context,flagged")
    assert json.loads(stix.read_text())["type"] == "bundle"


def test_missing_file_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", "/no/such/file.eml"]) == 2


def test_rules_and_samples(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    assert main(["samples"]) == 0
    out = capsys.readouterr().out
    assert "AUTH-DMARC-FAIL" in out and "CEO fraud" in out


def test_detections_doc_is_up_to_date() -> None:
    doc = Path(__file__).resolve().parent.parent / "docs" / "DETECTIONS.md"
    assert doc.read_text(encoding="utf-8") == detections_markdown() + "\n", (
        "docs/DETECTIONS.md is stale: run `dayag rules --markdown > docs/DETECTIONS.md`"
    )
