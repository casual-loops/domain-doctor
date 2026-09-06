from fastapi.testclient import TestClient

import app.main as main
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


def test_homepage():
    response = client.get("/")

    assert response.status_code == 200
    assert "Domain Doctor" in response.text
    assert "Know what the internet sees." in response.text


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


def test_report_page(monkeypatch):
    monkeypatch.setattr(
        main,
        "diagnose_host",
        lambda host: (
            "example.com",
            fake_results(),
        ),
    )

    response = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert response.status_code == 200
    assert "DIAGNOSTIC REPORT" in response.text
    assert "HEALTHY" in response.text


def test_blocked_report(monkeypatch):
    def blocked(host):
        raise TargetValidationError(
            "The hostname resolves to a non-public address."
        )

    monkeypatch.setattr(
        main,
        "diagnose_host",
        blocked,
    )

    response = client.get(
        "/check",
        params={"host": "localhost"},
    )

    assert response.status_code == 400
    assert "CHECK BLOCKED" in response.text
