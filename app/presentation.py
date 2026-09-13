from dataclasses import dataclass
from urllib.parse import urlsplit

from app.checks.http import HttpTrace, ResponseSnapshot
from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)


@dataclass(frozen=True)
class RedirectChange:
    label: str
    kind: str


@dataclass(frozen=True)
class RedirectHopView:
    response: ResponseSnapshot
    changes: tuple[RedirectChange, ...] = ()


@dataclass(frozen=True)
class SurfaceMatrixFamilyView:
    available: bool
    scanner_available: bool | None = None
    http_entry: str | None = None
    https_response: str | None = None
    tls: str | None = None
    final_host: str | None = None


@dataclass(frozen=True)
class SurfaceMatrixView:
    ipv4: SurfaceMatrixFamilyView
    ipv6: SurfaceMatrixFamilyView


def build_redirect_hops(trace: HttpTrace) -> list[RedirectHopView]:
    """Build presentation data for a redirect trace."""

    hops = []

    for index, response in enumerate(trace.responses):
        changes = []

        if index < len(trace.responses) - 1:
            current = urlsplit(response.url)
            next_response = trace.responses[index + 1]
            destination = urlsplit(next_response.url)

            if current.scheme != destination.scheme:
                if current.scheme == "http" and destination.scheme == "https":
                    changes.append(
                        RedirectChange(
                            label="SCHEME UPGRADE",
                            kind="upgrade",
                        )
                    )
                elif current.scheme == "https" and destination.scheme == "http":
                    changes.append(
                        RedirectChange(
                            label="SCHEME DOWNGRADE",
                            kind="downgrade",
                        )
                    )
                else:
                    changes.append(
                        RedirectChange(
                            label="SCHEME CHANGE",
                            kind="scheme",
                        )
                    )

            current_hostname = (current.hostname or "").lower()
            destination_hostname = (destination.hostname or "").lower()

            if current_hostname != destination_hostname:
                changes.append(
                    RedirectChange(
                        label="HOSTNAME CHANGE",
                        kind="hostname",
                    )
                )

        hops.append(
            RedirectHopView(
                response=response,
                changes=tuple(changes),
            )
        )

    return hops


def _surface_http_entry(
    result: AddressFamilyResult,
) -> str | None:
    trace = result.http_trace

    if trace is None or not trace.responses:
        return "No response"

    first = trace.responses[0]
    final = trace.final

    if final is not None:
        first_scheme = urlsplit(first.url).scheme
        final_scheme = urlsplit(final.url).scheme

        if (
            first_scheme == "http"
            and final_scheme == "https"
        ):
            return f"{first.status} → HTTPS"

    return str(first.status)


def _surface_https_response(
    result: AddressFamilyResult,
) -> str | None:
    trace = result.https_trace

    if trace is None:
        return None

    final = trace.final

    if final is None:
        return "No response"

    return str(final.status)


def _surface_tls(
    result: AddressFamilyResult,
) -> str | None:
    connection_result = next(
        (
            item
            for item in result.tls_results
            if item.name == "TLS connection"
        ),
        None,
    )

    if connection_result is None:
        return None

    if connection_result.status == "pass":
        return "Valid"

    if connection_result.status == "warn":
        return "Warning"

    return "Failed"


def _surface_final_host(
    result: AddressFamilyResult,
) -> str | None:
    trace = result.https_trace or result.http_trace

    if trace is None:
        return None

    final = trace.final

    if final is None:
        return "Not reached"

    return urlsplit(final.url).hostname


def _build_surface_family(
    result: AddressFamilyResult,
) -> SurfaceMatrixFamilyView:
    if not result.available:
        return SurfaceMatrixFamilyView(
            available=False,
            scanner_available=None,
        )

    if result.scanner_available is False:
        return SurfaceMatrixFamilyView(
            available=True,
            scanner_available=False,
            http_entry="Scanner unavailable",
            https_response="Scanner unavailable",
            tls="Scanner unavailable",
            final_host="Scanner unavailable",
        )

    return SurfaceMatrixFamilyView(
        available=True,
        scanner_available=True,
        http_entry=_surface_http_entry(result),
        https_response=_surface_https_response(result),
        tls=_surface_tls(result),
        final_host=_surface_final_host(result),
    )


def build_surface_matrix(
    diagnostics: AddressFamilyDiagnostics,
) -> SurfaceMatrixView:
    return SurfaceMatrixView(
        ipv4=_build_surface_family(
            diagnostics.ipv4,
        ),
        ipv6=_build_surface_family(
            diagnostics.ipv6,
        ),
    )