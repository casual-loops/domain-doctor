from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from app.diagnostics import (
    AddressFamilyDiagnostics,
    AddressFamilyResult,
)


ParityStatus = Literal["pass", "warn", "fail"]


@dataclass(frozen=True)
class ParityAnalysis:
    status: ParityStatus
    summary: str
    detail: str | None = None


def _final_https_status(
    result: AddressFamilyResult,
) -> int | None:
    trace = result.https_trace

    if trace is None:
        return None

    final = trace.final

    if final is None:
        return None

    return final.status


def _final_hostname(
    result: AddressFamilyResult,
) -> str | None:
    trace = result.https_trace

    if trace is None:
        return None

    final = trace.final

    if final is None:
        return None

    return urlsplit(final.url).hostname


def _tls_status(
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

    return connection_result.status


def _http_path_signature(
    result: AddressFamilyResult,
) -> tuple[
    tuple[tuple[int, str], ...],
    str | None,
] | None:
    trace = result.http_trace

    if trace is None:
        return None

    responses = tuple(
        (
            response.status,
            response.url,
        )
        for response in trace.responses
    )

    return responses, trace.error


def analyze_parity(
    diagnostics: AddressFamilyDiagnostics,
) -> ParityAnalysis:
    ipv4 = diagnostics.ipv4
    ipv6 = diagnostics.ipv6

    if not ipv4.available or not ipv6.available:
        return ParityAnalysis(
            status="pass",
            summary="IPv4 and IPv6 parity is not applicable.",
            detail=(
                "The hostname is not configured for both "
                "address families."
            ),
        )

    if (
        ipv4.scanner_available is False
        or ipv6.scanner_available is False
    ):
        return ParityAnalysis(
            status="pass",
            summary="IPv4 and IPv6 parity could not be compared.",
            detail=(
                "Domain Doctor cannot currently test both "
                "address families from this scanner."
            ),
        )

    ipv4_tls = _tls_status(ipv4)
    ipv6_tls = _tls_status(ipv6)

    ipv4_https = _final_https_status(ipv4)
    ipv6_https = _final_https_status(ipv6)

    ipv4_host = _final_hostname(ipv4)
    ipv6_host = _final_hostname(ipv6)

    ipv4_redirect = _http_path_signature(ipv4)
    ipv6_redirect = _http_path_signature(ipv6)

    if (
        ipv4_tls == ipv6_tls
        and ipv4_https == ipv6_https
        and ipv4_host == ipv6_host
        and ipv4_redirect == ipv6_redirect
    ):
        return ParityAnalysis(
            status="pass",
            summary="IPv4 and IPv6 behavior is consistent.",
        )

    ipv4_reached_https = ipv4_https is not None
    ipv6_reached_https = ipv6_https is not None

    if ipv4_reached_https != ipv6_reached_https:
        if ipv4_reached_https:
            return ParityAnalysis(
                status="fail",
                summary="IPv4 and IPv6 availability differs.",
                detail=(
                    f"IPv4 reached HTTPS with status {ipv4_https}, "
                    "but IPv6 did not reach an HTTPS response."
                ),
            )

        return ParityAnalysis(
            status="fail",
            summary="IPv4 and IPv6 availability differs.",
            detail=(
                f"IPv6 reached HTTPS with status {ipv6_https}, "
                "but IPv4 did not reach an HTTPS response."
            ),
        )

    if ipv4_https != ipv6_https:
        return ParityAnalysis(
            status="warn",
            summary="IPv4 and IPv6 behavior differs.",
            detail=(
                "Final HTTPS response differs: "
                f"IPv4 returned {ipv4_https}, "
                f"IPv6 returned {ipv6_https}."
            ),
        )

    if ipv4_tls != ipv6_tls:
      return ParityAnalysis(
          status="warn",
          summary="IPv4 and IPv6 behavior differs.",
          detail=(
              "TLS outcome differs: "
              f"IPv4 is {ipv4_tls}, "
              f"IPv6 is {ipv6_tls}."
          ),
      )

    if ipv4_host != ipv6_host:
        return ParityAnalysis(
            status="warn",
            summary="IPv4 and IPv6 behavior differs.",
            detail=(
                "Final hostname differs: "
                f"IPv4 reached {ipv4_host}, "
                f"IPv6 reached {ipv6_host}."
            ),
        )

    if ipv4_redirect != ipv6_redirect:
      return ParityAnalysis(
          status="warn",
          summary="IPv4 and IPv6 behavior differs.",
          detail=(
              "HTTP redirect path differs between IPv4 and IPv6."
          ),
      )

    return ParityAnalysis(
        status="warn",
        summary="IPv4 and IPv6 behavior differs.",
    )