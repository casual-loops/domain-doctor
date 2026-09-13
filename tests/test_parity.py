from app.checks.http import HttpTrace, ResponseSnapshot
from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)
from app.models import CheckResult
from app.parity import analyze_parity


def family_result(
    family,
    address,
    status=200,
    final_url="https://example.com/",
):
    return AddressFamilyResult(
        family=family,
        addresses=(address,),
        scanner_available=True,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="pass",
                summary="TLS succeeded.",
            ),
        ),
        https_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url=final_url,
                    address=address,
                    status=status,
                    reason="OK",
                    headers={},
                )
            ]
        ),
    )


def family_result_with_redirect(
    family,
    address,
    redirect_status=301,
):
    return AddressFamilyResult(
        family=family,
        addresses=(address,),
        scanner_available=True,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="pass",
                summary="TLS succeeded.",
            ),
        ),
        http_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url="http://example.com/",
                    address=address,
                    status=redirect_status,
                    reason="Moved",
                    headers={
                        "location": "https://example.com/",
                    },
                ),
                ResponseSnapshot(
                    url="https://example.com/",
                    address=address,
                    status=200,
                    reason="OK",
                    headers={},
                ),
            ]
        ),
        https_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url="https://example.com/",
                    address=address,
                    status=200,
                    reason="OK",
                    headers={},
                )
            ]
        ),
    )


def test_parity_warns_when_redirect_path_differs():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result_with_redirect(
            "ipv4",
            "93.184.216.34",
            redirect_status=301,
        ),
        ipv6=family_result_with_redirect(
            "ipv6",
            "2606:2800:220:1:248:1893:25c8:1946",
            redirect_status=302,
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "warn"
    assert result.summary == (
        "IPv4 and IPv6 behavior differs."
    )
    assert result.detail == (
        "HTTP redirect path differs between IPv4 and IPv6."
    )


def test_parity_passes_when_dual_stack_behavior_matches():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result(
            "ipv4",
            "93.184.216.34",
        ),
        ipv6=family_result(
            "ipv6",
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "pass"
    assert result.summary == (
        "IPv4 and IPv6 behavior is consistent."
    )


def test_parity_warns_when_final_https_status_differs():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result(
            "ipv4",
            "93.184.216.34",
            status=200,
        ),
        ipv6=family_result(
            "ipv6",
            "2606:2800:220:1:248:1893:25c8:1946",
            status=403,
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "warn"
    assert result.summary == (
        "IPv4 and IPv6 behavior differs."
    )
    assert result.detail == (
        "Final HTTPS response differs: "
        "IPv4 returned 200, IPv6 returned 403."
    )


def test_parity_fails_when_only_one_family_reaches_https():
    ipv4 = family_result(
        "ipv4",
        "93.184.216.34",
        status=200,
    )

    ipv6 = AddressFamilyResult(
        family="ipv6",
        addresses=(
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
        scanner_available=True,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="fail",
                summary="TLS connection failed.",
            ),
        ),
        https_trace=HttpTrace(
            responses=[],
            error="Connection failed.",
        ),
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    result = analyze_parity(diagnostics)

    assert result.status == "fail"
    assert result.summary == (
        "IPv4 and IPv6 availability differs."
    )
    assert result.detail == (
        "IPv4 reached HTTPS with status 200, "
        "but IPv6 did not reach an HTTPS response."
    )


def test_parity_is_not_applicable_for_single_stack_target():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result(
            "ipv4",
            "93.184.216.34",
            status=200,
        ),
        ipv6=AddressFamilyResult(
            family="ipv6",
            addresses=(),
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "not_applicable"
    assert result.summary == (
        "IPv4 and IPv6 parity is not applicable."
    )
    assert result.detail == (
        "The hostname is not configured for both "
        "address families."
    )


def test_parity_is_unavailable_when_scanner_cannot_test_both_families():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result(
            "ipv4",
            "93.184.216.34",
            status=200,
        ),
        ipv6=AddressFamilyResult(
            family="ipv6",
            addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
            scanner_available=False,
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "unavailable"
    assert result.summary == (
        "IPv4 and IPv6 parity could not be compared."
    )
    assert result.detail == (
        "Domain Doctor cannot currently test both "
        "address families from this scanner."
    )


def test_parity_warns_when_final_hostname_differs():
    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=family_result(
            "ipv4",
            "93.184.216.34",
            final_url="https://www.example.com/",
        ),
        ipv6=family_result(
            "ipv6",
            "2606:2800:220:1:248:1893:25c8:1946",
            final_url="https://example.com/",
        ),
    )

    result = analyze_parity(diagnostics)

    assert result.status == "warn"
    assert result.summary == (
        "IPv4 and IPv6 behavior differs."
    )
    assert result.detail == (
        "Final hostname differs: "
        "IPv4 reached www.example.com, "
        "IPv6 reached example.com."
    )


def test_parity_warns_when_tls_outcome_differs():
    ipv4 = family_result(
        "ipv4",
        "93.184.216.34",
        status=200,
    )

    ipv6 = family_result(
        "ipv6",
        "2606:2800:220:1:248:1893:25c8:1946",
        status=200,
    )

    ipv6 = AddressFamilyResult(
        family=ipv6.family,
        addresses=ipv6.addresses,
        scanner_available=ipv6.scanner_available,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="warn",
                summary="TLS completed with a warning.",
            ),
        ),
        http_results=ipv6.http_results,
        http_trace=ipv6.http_trace,
        https_trace=ipv6.https_trace,
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    result = analyze_parity(diagnostics)

    assert result.status == "warn"
    assert result.summary == (
        "IPv4 and IPv6 behavior differs."
    )
    assert result.detail == (
        "TLS outcome differs: IPv4 is pass, IPv6 is warn."
    )


def test_parity_passes_when_both_families_fail_the_same_way():
    ipv4 = AddressFamilyResult(
        family="ipv4",
        addresses=("93.184.216.34",),
        scanner_available=True,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="fail",
                summary="TLS connection failed.",
            ),
        ),
        https_trace=HttpTrace(
            responses=[],
            error="Connection refused.",
        ),
    )

    ipv6 = AddressFamilyResult(
        family="ipv6",
        addresses=(
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
        scanner_available=True,
        tls_results=(
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="fail",
                summary="TLS connection failed.",
            ),
        ),
        https_trace=HttpTrace(
            responses=[],
            error="Connection refused.",
        ),
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    result = analyze_parity(diagnostics)

    assert result.status == "pass"
    assert result.summary == (
        "IPv4 and IPv6 behavior is consistent."
    )