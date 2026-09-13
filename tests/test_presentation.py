from app.checks.http import HttpTrace, ResponseSnapshot
from app.presentation import build_redirect_hops
from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)
from app.models import CheckResult
from app.presentation import build_surface_matrix


def snapshot(url: str, status: int = 200) -> ResponseSnapshot:
    return ResponseSnapshot(
        url=url,
        address="93.184.216.34",
        status=status,
        reason="OK",
        headers={},
    )


def test_build_redirect_hops_marks_scheme_upgrade():
    trace = HttpTrace(
        responses=[
            snapshot("http://example.com/", 301),
            snapshot("https://example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME UPGRADE"
    ]
    assert hops[0].changes[0].kind == "upgrade"
    assert hops[1].changes == ()


def test_build_redirect_hops_marks_hostname_change():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/", 302),
            snapshot("https://www.example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "HOSTNAME CHANGE"
    ]
    assert hops[0].changes[0].kind == "hostname"


def test_build_redirect_hops_can_mark_multiple_changes():
    trace = HttpTrace(
        responses=[
            snapshot("http://example.com/", 301),
            snapshot("https://www.example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME UPGRADE",
        "HOSTNAME CHANGE",
    ]


def test_build_redirect_hops_marks_scheme_downgrade():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/", 302),
            snapshot("http://example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME DOWNGRADE"
    ]
    assert hops[0].changes[0].kind == "downgrade"


def test_build_redirect_hops_leaves_same_origin_unannotated():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/start", 302),
            snapshot("https://example.com/final"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert hops[0].changes == ()
    assert hops[1].changes == ()


from app.checks.http import HttpTrace, ResponseSnapshot
from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)
from app.models import CheckResult
from app.presentation import build_surface_matrix


def test_surface_matrix_builds_ipv4_view_and_marks_ipv6_unavailable():
    ipv4 = AddressFamilyResult(
        family="ipv4",
        addresses=("93.184.216.34",),
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
        ),
        https_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url="https://example.com/",
                    address="93.184.216.34",
                    status=200,
                    reason="OK",
                    headers={},
                )
            ]
        ),
    )

    ipv6 = AddressFamilyResult(
        family="ipv6",
        addresses=(),
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    matrix = build_surface_matrix(diagnostics)

    assert matrix.ipv4.available is True
    assert matrix.ipv4.http_entry == "301 → HTTPS"
    assert matrix.ipv4.https_response == "200"
    assert matrix.ipv4.tls == "Valid"
    assert matrix.ipv4.final_host == "example.com"

    assert matrix.ipv6.available is False


def test_surface_matrix_builds_dual_stack_columns():
    ipv4 = AddressFamilyResult(
        family="ipv4",
        addresses=("93.184.216.34",),
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
                    address="93.184.216.34",
                    status=301,
                    reason="Moved Permanently",
                    headers={
                        "location": "https://www.example.com/",
                    },
                ),
                ResponseSnapshot(
                    url="https://www.example.com/",
                    address="93.184.216.34",
                    status=200,
                    reason="OK",
                    headers={},
                ),
            ]
        ),
        https_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url="https://www.example.com/",
                    address="93.184.216.34",
                    status=200,
                    reason="OK",
                    headers={},
                )
            ]
        ),
    )

    ipv6 = AddressFamilyResult(
        family="ipv6",
        addresses=(
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
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
                    address="2606:2800:220:1:248:1893:25c8:1946",
                    status=301,
                    reason="Moved Permanently",
                    headers={
                        "location": "https://example.com/",
                    },
                ),
                ResponseSnapshot(
                    url="https://example.com/",
                    address="2606:2800:220:1:248:1893:25c8:1946",
                    status=403,
                    reason="Forbidden",
                    headers={},
                ),
            ]
        ),
        https_trace=HttpTrace(
            responses=[
                ResponseSnapshot(
                    url="https://example.com/",
                    address="2606:2800:220:1:248:1893:25c8:1946",
                    status=403,
                    reason="Forbidden",
                    headers={},
                )
            ]
        ),
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    matrix = build_surface_matrix(diagnostics)

    assert matrix.ipv4.available is True
    assert matrix.ipv6.available is True

    assert matrix.ipv4.http_entry == "301 → HTTPS"
    assert matrix.ipv6.http_entry == "301 → HTTPS"

    assert matrix.ipv4.https_response == "200"
    assert matrix.ipv6.https_response == "403"

    assert matrix.ipv4.tls == "Valid"
    assert matrix.ipv6.tls == "Valid"

    assert matrix.ipv4.final_host == "www.example.com"
    assert matrix.ipv6.final_host == "example.com"


def test_surface_matrix_marks_scanner_unavailable():
    ipv4 = AddressFamilyResult(
        family="ipv4",
        addresses=("93.184.216.34",),
        scanner_available=True,
    )

    ipv6 = AddressFamilyResult(
        family="ipv6",
        addresses=(
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
        scanner_available=False,
    )

    diagnostics = AddressFamilyDiagnostics(
        hostname="example.com",
        ipv4=ipv4,
        ipv6=ipv6,
    )

    matrix = build_surface_matrix(diagnostics)

    assert matrix.ipv6.available is True
    assert matrix.ipv6.scanner_available is False
    assert matrix.ipv6.http_entry == "Scanner unavailable"
    assert matrix.ipv6.https_response == "Scanner unavailable"
    assert matrix.ipv6.tls == "Scanner unavailable"
    assert matrix.ipv6.final_host == "Scanner unavailable"