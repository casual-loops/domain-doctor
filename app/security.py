import ipaddress
import re
import socket

from dataclasses import dataclass


class TargetValidationError(ValueError):
    """Raised when a requested target is invalid or unsafe."""


_LABEL_PATTERN = re.compile(
    r"^(?!-)[A-Z0-9-]{1,63}(?<!-)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidatedTarget:
    hostname: str
    ipv4_addresses: tuple[str, ...]
    ipv6_addresses: tuple[str, ...]


def normalize_hostname(value: str) -> str:
    """Normalize and validate a user-supplied hostname."""

    hostname = value.strip().rstrip(".")

    if not hostname:
        raise TargetValidationError("A hostname is required.")

    if "://" in hostname:
        raise TargetValidationError(
            "Enter a hostname only, without http:// or https://."
        )

    if any(character in hostname for character in "/?#@"):
        raise TargetValidationError(
            "URLs, paths, queries, and user information are not allowed."
        )

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise TargetValidationError(
            "IP addresses are not accepted. Enter a public hostname."
        )

    if ":" in hostname:
        raise TargetValidationError(
            "Ports are not accepted. Enter a hostname only."
        )

    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError(
            "The hostname contains invalid characters."
        ) from exc

    if len(hostname) > 253:
        raise TargetValidationError("The hostname is too long.")

    labels = hostname.split(".")

    if len(labels) < 2:
        raise TargetValidationError(
            "Enter a fully qualified public hostname."
        )

    for label in labels:
        if not _LABEL_PATTERN.fullmatch(label):
            raise TargetValidationError(
                f"Invalid hostname label: {label!r}"
            )

    return hostname


def resolve_target(value: str) -> ValidatedTarget:
    """
    Normalize a hostname, resolve it, validate every returned address,
    and preserve IPv4 and IPv6 addresses separately.
    """

    hostname = normalize_hostname(value)

    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise TargetValidationError(
            "The hostname could not be resolved."
        ) from exc

    addresses = sorted(
        {
            record[4][0]
            for record in records
        }
    )

    if not addresses:
        raise TargetValidationError(
            "The hostname did not resolve to any addresses."
        )

    ipv4_addresses = []
    ipv6_addresses = []

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if not ip.is_global:
            raise TargetValidationError(
                f"The hostname resolves to a non-public address: {address}"
            )

        if ip.version == 4:
            ipv4_addresses.append(address)
        else:
            ipv6_addresses.append(address)

    return ValidatedTarget(
        hostname=hostname,
        ipv4_addresses=tuple(ipv4_addresses),
        ipv6_addresses=tuple(ipv6_addresses),
    )


def validate_target(value: str) -> tuple[str, list[str]]:
    """
    Preserve the existing target-validation contract.

    New code should prefer resolve_target() when address-family
    information is needed.
    """

    target = resolve_target(value)

    addresses = sorted(
        [
            *target.ipv4_addresses,
            *target.ipv6_addresses,
        ]
    )

    return target.hostname, addresses