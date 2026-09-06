from datetime import datetime, timedelta, timezone

import app.checks.tls as tls_checks
from app.checks.tls import (
    _dns_name_matches,
    check_tls,
)


class FakeCertificate:
    def __init__(self):
        now = datetime.now(timezone.utc)

        self.not_valid_before_utc = (
            now - timedelta(days=1)
        )

        self.not_valid_after_utc = (
            now + timedelta(days=60)
        )


def test_dns_name_exact_match():
    assert _dns_name_matches(
        "example.com",
        "example.com",
    )


def test_dns_name_wildcard_match():
    assert _dns_name_matches(
        "*.example.com",
        "www.example.com",
    )


def test_dns_name_wildcard_does_not_match_multiple_levels():
    assert not _dns_name_matches(
        "*.example.com",
        "a.b.example.com",
    )


def test_tls_success(monkeypatch):
    certificate = FakeCertificate()

    monkeypatch.setattr(
        tls_checks,
        "_fetch_certificate",
        lambda hostname, address: (
            certificate,
            "TLSv1.3",
            "TEST-CIPHER",
        ),
    )

    monkeypatch.setattr(
        tls_checks,
        "_certificate_dns_names",
        lambda certificate: ["example.com"],
    )

    monkeypatch.setattr(
        tls_checks,
        "_verify_certificate",
        lambda hostname, address: None,
    )

    results = check_tls(
        "example.com",
        ["93.184.216.34"],
    )

    assert len(results) == 5
    assert all(result.status == "pass" for result in results)


def test_tls_connection_failure(monkeypatch):
    def fail_fetch(hostname, address):
        raise OSError("Connection refused")

    monkeypatch.setattr(
        tls_checks,
        "_fetch_certificate",
        fail_fetch,
    )

    results = check_tls(
        "example.com",
        ["93.184.216.34"],
    )

    assert len(results) == 1
    assert results[0].status == "fail"
