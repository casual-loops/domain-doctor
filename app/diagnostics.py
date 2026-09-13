from dataclasses import dataclass
from typing import Literal

from app.checks.http import (
    HttpTrace,
    check_http,
    inspect_http,
    inspect_https,
)
from app.checks.tls import check_tls
from app.models import CheckResult
from app.security import resolve_target


AddressFamily = Literal["ipv4", "ipv6"]


@dataclass(frozen=True)
class AddressFamilyResult:
    family: AddressFamily
    addresses: tuple[str, ...]
    tls_results: tuple[CheckResult, ...] = ()
    http_results: tuple[CheckResult, ...] = ()
    http_trace: HttpTrace | None = None
    https_trace: HttpTrace | None = None

    @property
    def available(self) -> bool:
        return bool(self.addresses)


@dataclass(frozen=True)
class AddressFamilyDiagnostics:
    hostname: str
    ipv4: AddressFamilyResult
    ipv6: AddressFamilyResult


def _diagnose_family(
    hostname: str,
    family: AddressFamily,
    addresses: tuple[str, ...],
) -> AddressFamilyResult:
    if not addresses:
        return AddressFamilyResult(
            family=family,
            addresses=(),
        )

    address_list = list(addresses)

    tls_results = check_tls(
        hostname,
        address_list,
        address_family=family,
    )

    http_trace = inspect_http(
        hostname,
        address_family=family,
    )

    https_trace = inspect_https(
        hostname,
        address_family=family,
    )

    http_results = check_http(
        hostname,
        address_list,
        http_trace=http_trace,
        https_trace=https_trace,
    )

    return AddressFamilyResult(
        family=family,
        addresses=addresses,
        tls_results=tuple(tls_results),
        http_results=tuple(http_results),
        http_trace=http_trace,
        https_trace=https_trace,
    )


def diagnose_address_families(
    host: str,
) -> AddressFamilyDiagnostics:
    target = resolve_target(host)

    ipv4 = _diagnose_family(
        target.hostname,
        "ipv4",
        target.ipv4_addresses,
    )

    ipv6 = _diagnose_family(
        target.hostname,
        "ipv6",
        target.ipv6_addresses,
    )

    return AddressFamilyDiagnostics(
        hostname=target.hostname,
        ipv4=ipv4,
        ipv6=ipv6,
    )