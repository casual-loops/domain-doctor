import socket

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
    scanner_available: bool | None = None
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


def _scanner_can_route(
    family: AddressFamily,
    addresses: tuple[str, ...],
) -> bool:
    """
    Determine whether the local scanner has a route for this address family.

    UDP connect does not establish a remote connection or transmit
    application data. It asks the operating system to select a route.
    """

    socket_family = (
        socket.AF_INET
        if family == "ipv4"
        else socket.AF_INET6
    )

    for address in addresses:
        sock = socket.socket(
            socket_family,
            socket.SOCK_DGRAM,
        )

        try:
            if family == "ipv4":
                destination = (address, 443)
            else:
                destination = (address, 443, 0, 0)

            sock.connect(destination)

            return True

        except OSError:
            continue

        finally:
            sock.close()

    return False


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

    if not _scanner_can_route(
        family,
        addresses,
    ):
        return AddressFamilyResult(
            family=family,
            addresses=addresses,
            scanner_available=False,
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
        scanner_available=True,
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