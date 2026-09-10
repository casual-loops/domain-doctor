from fastapi.testclient import TestClient

import app.main as main
from app.checks.http import HttpTrace, ResponseSnapshot
from app.models import CheckResult
from app.security import TargetValidationError


client = TestClient(main.app)


def fake_results():
    return [
        CheckResult(
            name="DNS resolution",
            category="DNS",
            status="pass",
            summary="Hostname resolves successfully.",
            detail="example.com resolved successfully.",
        )
    ]


def fake_diagnosis_with_traces(host):
    return (
        "example.com",
        fake_results(),
        HttpTrace(responses=[]),
        HttpTrace(responses=[]),
    )


def fake_diagnosis_with_visible_redirects(host):
    results = fake_results() + [
        CheckResult(
            name="HTTP reachability",
            category="HTTP",
            status="pass",
            summary="HTTP responded with status 301.",
            detail="Connected successfully.",
        )
    ]

    http_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="http://example.com/",
                address="93.184.216.34",
                status=301,
                reason="Moved Permanently",
                headers={
                    "location": "https://example.com/"
                },
            ),
            ResponseSnapshot(
                url="https://example.com/",
                address="93.184.216.34",
                status=200,
                reason="OK",
                headers={},
            ),
        ]
    )

    https_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="https://example.com/",
                address="93.184.216.34",
                status=200,
                reason="OK",
                headers={},
            )
        ]
    )

    return (
        "example.com",
        results,
        http_trace,
        https_trace,
    )


def test_homepage():
    response = client.get("/")

    assert response.status_code == 200
    assert "Domain Doctor" in response.text
    assert "Know what the internet sees." in response.text


def test_privacy_page():
    response = client.get("/privacy")

    assert response.status_code == 200
    assert "Minimal data. Useful signals." in response.text
    assert "Umami Cloud" in response.text


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_check(monkeypatch):
    monkeypatch.setattr(
        main,
        "diagnose_host",
        lambda host: (
            "example.com",
            fake_results(),
        ),
    )

    response = client.get(
        "/api/check",
        params={"host": "example.com"},
    )

    assert response.status_code == 200
    assert response.json()["hostname"] == "example.com"
    assert "http_trace" not in response.json()
    assert "https_trace" not in response.json()


def test_report_page(monkeypatch):
    monkeypatch.setattr(
        main,
        "diagnose_host_with_traces",
        fake_diagnosis_with_traces,
    )

    response = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert response.status_code == 200
    assert "DIAGNOSTIC REPORT" in response.text
    assert "HEALTHY" in response.text


def test_report_renders_redirect_chain(monkeypatch):
    monkeypatch.setattr(
        main,
        "diagnose_host_with_traces",
        fake_diagnosis_with_visible_redirects,
    )

    response = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert response.status_code == 200
    assert "REDIRECT CHAIN" in response.text
    assert "Observed request paths" in response.text
    assert "http://example.com/" in response.text
    assert "https://example.com/" in response.text
    assert "Moved Permanently" in response.text
    assert "FINAL" in response.text


def test_blocked_report(monkeypatch):
    def blocked(host):
        raise TargetValidationError(
            "The hostname resolves to a non-public address."
        )

    monkeypatch.setattr(
        main,
        "diagnose_host_with_traces",
        blocked,
    )

    response = client.get(
        "/check",
        params={"host": "localhost"},
    )

    assert response.status_code == 400
    assert "CHECK BLOCKED" in response.text
