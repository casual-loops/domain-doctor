import app.diagnostics as diagnostics
from app.security import ValidatedTarget
from app.models import CheckResult
from app.checks.http import HttpTrace, ResponseSnapshot


def test_address_family_diagnostics_represents_unavailable_ipv6(
    monkeypatch,
):
    monkeypatch.setattr(
        diagnostics,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(),
        ),
    )

    monkeypatch.setattr(
        diagnostics,
        "_diagnose_family",
        lambda hostname, family, addresses: (
            diagnostics.AddressFamilyResult(
                family=family,
                addresses=tuple(addresses),
            )
        ),
    )

    result = diagnostics.diagnose_address_families(
        "example.com"
    )

    assert result.hostname == "example.com"

    assert result.ipv4.available is True
    assert result.ipv4.addresses == (
        "93.184.216.34",
    )

    assert result.ipv6.available is False
    assert result.ipv6.addresses == ()


def test_address_family_diagnostics_runs_each_family_separately(
    monkeypatch,
):
    calls = []

    monkeypatch.setattr(
        diagnostics,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
        ),
    )

    def fake_diagnose_family(
        hostname,
        family,
        addresses,
    ):
        calls.append(
            (
                hostname,
                family,
                addresses,
            )
        )

        return diagnostics.AddressFamilyResult(
            family=family,
            addresses=addresses,
        )

    monkeypatch.setattr(
        diagnostics,
        "_diagnose_family",
        fake_diagnose_family,
    )

    result = diagnostics.diagnose_address_families(
        "example.com"
    )

    assert result.hostname == "example.com"

    assert calls == [
        (
            "example.com",
            "ipv4",
            ("93.184.216.34",),
        ),
        (
            "example.com",
            "ipv6",
            (
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
        ),
    ]

    assert result.ipv4.family == "ipv4"
    assert result.ipv6.family == "ipv6"


def test_diagnose_family_collects_family_specific_results(
    monkeypatch,
):
    calls = []

    tls_results = [
        CheckResult(
            name="TLS connection",
            category="TLS",
            status="pass",
            summary="TLS succeeded.",
            detail="Synthetic TLS result.",
        )
    ]

    http_results = [
        CheckResult(
            name="HTTPS response",
            category="HTTP",
            status="pass",
            summary="HTTPS returned status 200.",
            detail="Synthetic HTTP result.",
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
                    "location": "https://example.com/",
                },
            )
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

    def fake_check_tls(
        hostname,
        addresses,
        address_family=None,
    ):
        calls.append(
            (
                "tls",
                hostname,
                tuple(addresses),
                address_family,
            )
        )
        return tls_results

    def fake_inspect_http(
        hostname,
        address_family=None,
    ):
        calls.append(
            (
                "http-trace",
                hostname,
                address_family,
            )
        )
        return http_trace

    def fake_inspect_https(
        hostname,
        address_family=None,
    ):
        calls.append(
            (
                "https-trace",
                hostname,
                address_family,
            )
        )
        return https_trace

    def fake_check_http(
        hostname,
        addresses,
        http_trace=None,
        https_trace=None,
    ):
        calls.append(
            (
                "http-results",
                hostname,
                tuple(addresses),
                http_trace,
                https_trace,
            )
        )
        return http_results

    monkeypatch.setattr(
        diagnostics,
        "check_tls",
        fake_check_tls,
    )

    monkeypatch.setattr(
        diagnostics,
        "inspect_http",
        fake_inspect_http,
    )

    monkeypatch.setattr(
        diagnostics,
        "inspect_https",
        fake_inspect_https,
    )

    monkeypatch.setattr(
        diagnostics,
        "check_http",
        fake_check_http,
    )

    result = diagnostics._diagnose_family(
        "example.com",
        "ipv4",
        ("93.184.216.34",),
    )

    assert result.family == "ipv4"
    assert result.available is True
    assert result.addresses == (
        "93.184.216.34",
    )

    assert result.tls_results == tuple(tls_results)
    assert result.http_results == tuple(http_results)
    assert result.http_trace is http_trace
    assert result.https_trace is https_trace

    assert calls == [
        (
            "tls",
            "example.com",
            ("93.184.216.34",),
            "ipv4",
        ),
        (
            "http-trace",
            "example.com",
            "ipv4",
        ),
        (
            "https-trace",
            "example.com",
            "ipv4",
        ),
        (
            "http-results",
            "example.com",
            ("93.184.216.34",),
            http_trace,
            https_trace,
        ),
    ]


def test_address_family_diagnostics_preserves_independent_outcomes(
    monkeypatch,
):
    monkeypatch.setattr(
        diagnostics,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
        ),
    )

    def fake_diagnose_family(
        hostname,
        family,
        addresses,
    ):
        status = "pass" if family == "ipv4" else "fail"

        return diagnostics.AddressFamilyResult(
            family=family,
            addresses=addresses,
            tls_results=(
                CheckResult(
                    name="TLS connection",
                    category="TLS",
                    status=status,
                    summary=(
                        "TLS succeeded."
                        if family == "ipv4"
                        else "TLS failed."
                    ),
                ),
            ),
        )

    monkeypatch.setattr(
        diagnostics,
        "_diagnose_family",
        fake_diagnose_family,
    )

    result = diagnostics.diagnose_address_families(
        "example.com"
    )

    assert result.ipv4.tls_results[0].status == "pass"
    assert result.ipv6.tls_results[0].status == "fail"

    assert result.ipv4.available is True
    assert result.ipv6.available is True