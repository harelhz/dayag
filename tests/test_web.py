from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from dayag.config import Config
from dayag.demo import get_sample
from dayag.parsing import MAX_EMAIL_BYTES
from dayag.web.app import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Config()))


def sample(name: str) -> bytes:
    found = get_sample(name)
    assert found is not None
    return found.read()


def test_index(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Analyze a suspicious email" in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"


def test_upload(client: TestClient) -> None:
    response = client.post(
        "/analyze", files={"file": ("x.eml", sample("02-paypal-homoglyph.eml"), "message/rfc822")}
    )
    assert response.status_code == 200
    assert "Malicious" in response.text
    assert 'download="dayag-' in response.text


def test_paste(client: TestClient) -> None:
    raw = sample("04-ceo-fraud.eml").decode()
    response = client.post("/analyze", data={"raw": raw})
    assert "Likely phishing" in response.text


def test_empty_submission(client: TestClient) -> None:
    response = client.post("/analyze", data={"raw": "  "})
    assert response.status_code == 400


def test_sample_button_only_accepts_known_samples(client: TestClient) -> None:
    assert client.post("/analyze/sample", data={"name": "04-ceo-fraud.eml"}).status_code == 200
    assert client.post("/analyze/sample", data={"name": "../../etc/passwd"}).status_code == 404


def test_api(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        content=sample("03-html-smuggling-invoice.eml"),
        headers={"Content-Type": "message/rfc822"},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "malicious"
    assert client.post("/api/analyze", content=b"").status_code == 400


def test_too_large(client: TestClient) -> None:
    response = client.post("/api/analyze", content=b"x" * (MAX_EMAIL_BYTES + 2 * 1024 * 1024))
    assert response.status_code == 413


def test_static_and_health(client: TestClient) -> None:
    assert client.get("/static/dayag.css").status_code == 200
    assert client.get("/healthz").json()["status"] == "ok"
