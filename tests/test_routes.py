from fastapi.testclient import TestClient

import app.main as main
from app.checks.http import HttpTrace, ResponseSnapshot
from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)
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


def fake_address_family_diagnostics():
    return AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=AddressFamilyResult(
            family="ipv4",
            addresses=("93.184.216.34",),
            scanner_available=True,
        ),
        ipv6=AddressFamilyResult(
            family="ipv6",
            addresses=(),
        ),
    )


def fake_diagnosis_with_traces(host):
    return (
        "example.com",
        fake_results(),
        HttpTrace(responses=[]),
        HttpTrace(responses=[]),
        fake_address_family_diagnostics(),
    )


def fake_diagnosis_with_visible_redirects(host):
    results = fake_results() + [
        CheckResult(
            name="HTTP reachability",
            category="HTTP",
            status="pass",
            summary="HTTP responded with status 301.",
            detail="Connected successfully.",
        ),
        CheckResult(
            name="HTTP to HTTPS redirect",
            category="HTTP",
            status="pass",
            summary="HTTP redirects to HTTPS.",
            detail=(
                "301 http://example.com/ -> "
                "200 https://example.com/"
            ),
        ),
        CheckResult(
            name="HTTPS response",
            category="HTTP",
            status="pass",
            summary="HTTPS returned status 200.",
            detail="200 https://example.com/",
        ),
    ]

    http_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="http://example.com/",
                address="93.184.216.34",
                status=301,
                reason="Moved Permanently",
                headers={
                    "location": "https://example.com/",
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

    address_family_diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=AddressFamilyResult(
            family="ipv4",
            addresses=("93.184.216.34",),
            scanner_available=True,
            tls_results=(
                CheckResult(
                    name="TLS connection",
                    category="TLS",
                    status="pass",
                    summary="TLS succeeded.",
                ),
            ),
            http_trace=http_trace,
            https_trace=https_trace,
        ),
        ipv6=AddressFamilyResult(
            family="ipv6",
            addresses=(),
        ),
    )

    return (
        "example.com",
        results,
        http_trace,
        https_trace,
        address_family_diagnostics,
    )


def fake_diagnosis_with_scanner_unavailable(host):
    address_family_diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=AddressFamilyResult(
            family="ipv4",
            addresses=("93.184.216.34",),
            scanner_available=True,
        ),
        ipv6=AddressFamilyResult(
            family="ipv6",
            addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
            scanner_available=False,
        ),
    )

    return (
        "example.com",
        fake_results(),
        HttpTrace(responses=[]),
        HttpTrace(responses=[]),
        address_family_diagnostics,
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
    assert "Redirect chain" in response.text
    assert "View chain" in response.text
    assert "HTTP ENTRY" in response.text
    assert "HTTPS ENTRY" in response.text
    assert "http://example.com/" in response.text
    assert "https://example.com/" in response.text
    assert "Moved Permanently" in response.text
    assert "FINAL" in response.text


def test_report_renders_surface_matrix_scanner_unavailable(
    monkeypatch,
):
    monkeypatch.setattr(
        main,
        "diagnose_host_with_traces",
        fake_diagnosis_with_scanner_unavailable,
    )

    response = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert response.status_code == 200
    assert "Surface Matrix" in response.text
    assert "Scanner unavailable" in response.text


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