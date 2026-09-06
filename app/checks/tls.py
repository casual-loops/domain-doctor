import ipaddress
import math
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.models import CheckResult


_TIMEOUT_SECONDS = 5
_EXPIRY_WARNING_DAYS = 30


def _open_socket(address: str) -> socket.socket:
    """Connect directly to an already validated IP address."""

    ip = ipaddress.ip_address(address)

    if ip.version == 4:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        destination = (address, 443)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        destination = (address, 443, 0, 0)

    sock.settimeout(_TIMEOUT_SECONDS)
    sock.connect(destination)

    return sock


def _fetch_certificate(
    hostname: str,
    address: str,
) -> tuple[x509.Certificate, str | None, str | None]:
    """
    Perform a TLS handshake against a validated IP address.

    Certificate verification is disabled here so Domain Doctor can inspect
    certificates that are expired, self-signed, or otherwise invalid.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with _open_socket(address) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        ) as tls_socket:
            certificate_der = tls_socket.getpeercert(binary_form=True)

            if certificate_der is None:
                raise ssl.SSLError("The server did not provide a certificate.")

            certificate = x509.load_der_x509_certificate(certificate_der)

            cipher = tls_socket.cipher()
            cipher_name = cipher[0] if cipher else None

            return certificate, tls_socket.version(), cipher_name


def _verify_certificate(hostname: str, address: str) -> str | None:
    """
    Perform normal browser-style certificate verification.

    Returns None when verification succeeds, otherwise an explanation.
    """

    context = ssl.create_default_context()

    try:
        with _open_socket(address) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ):
                return None

    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc)

    except ssl.SSLError as exc:
        return str(exc)


def _certificate_dns_names(certificate: x509.Certificate) -> list[str]:
    """Return DNS names advertised by the certificate."""

    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        names = extension.value.get_values_for_type(x509.DNSName)

        if names:
            return names

    except x509.ExtensionNotFound:
        pass

    common_names = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    return [attribute.value for attribute in common_names]


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    """Match a hostname against an exact or left-most wildcard DNS name."""

    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")

    if pattern.startswith("*."):
        suffix = pattern[2:]

        return (
            hostname.endswith("." + suffix)
            and hostname.count(".") == suffix.count(".") + 1
        )

    return pattern == hostname


def check_tls(
    hostname: str,
    addresses: list[str],
) -> list[CheckResult]:
    """Inspect TLS and certificate health for a validated target."""

    ordered_addresses = sorted(
        addresses,
        key=lambda address: (
            ipaddress.ip_address(address).version,
            address,
        ),
    )

    certificate = None
    protocol = None
    cipher = None
    selected_address = None
    errors = []

    for address in ordered_addresses:
        try:
            certificate, protocol, cipher = _fetch_certificate(
                hostname,
                address,
            )
            selected_address = address
            break

        except (OSError, ssl.SSLError) as exc:
            errors.append(f"{address}: {exc}")

    if certificate is None or selected_address is None:
        return [
            CheckResult(
                name="TLS connection",
                category="TLS",
                status="fail",
                summary="A TLS connection could not be established.",
                detail="; ".join(errors),
            )
        ]

    results = [
        CheckResult(
            name="TLS connection",
            category="TLS",
            status="pass",
            summary="A TLS handshake completed successfully.",
            detail=(
                f"{selected_address} negotiated "
                f"{protocol or 'unknown protocol'} using "
                f"{cipher or 'an unknown cipher'}."
            ),
        )
    ]

    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    if now < not_before:
        results.append(
            CheckResult(
                name="Certificate validity",
                category="TLS",
                status="fail",
                summary="The certificate is not valid yet.",
                detail=f"Validity begins {not_before.isoformat()}.",
            )
        )

    elif now >= not_after:
        results.append(
            CheckResult(
                name="Certificate validity",
                category="TLS",
                status="fail",
                summary="The certificate has expired.",
                detail=f"Certificate expired {not_after.isoformat()}.",
            )
        )

    else:
        results.append(
            CheckResult(
                name="Certificate validity",
                category="TLS",
                status="pass",
                summary="The certificate is currently within its validity period.",
                detail=(
                    f"Valid from {not_before.date()} through "
                    f"{not_after.date()}."
                ),
            )
        )

    seconds_remaining = (not_after - now).total_seconds()
    days_remaining = math.ceil(seconds_remaining / 86400)

    if days_remaining < 0:
        expiration_status = "fail"
        expiration_summary = "The certificate has expired."

    elif days_remaining <= _EXPIRY_WARNING_DAYS:
        expiration_status = "warn"
        expiration_summary = (
            f"The certificate expires in {days_remaining} day(s)."
        )

    else:
        expiration_status = "pass"
        expiration_summary = (
            f"The certificate expires in {days_remaining} days."
        )

    results.append(
        CheckResult(
            name="Certificate expiration",
            category="TLS",
            status=expiration_status,
            summary=expiration_summary,
            detail=f"Expiration date: {not_after.date()}.",
        )
    )

    dns_names = _certificate_dns_names(certificate)

    hostname_matches = any(
        _dns_name_matches(name, hostname)
        for name in dns_names
    )

    if hostname_matches:
        results.append(
            CheckResult(
                name="Certificate hostname",
                category="TLS",
                status="pass",
                summary="The certificate covers this hostname.",
                detail=", ".join(dns_names),
            )
        )
    else:
        results.append(
            CheckResult(
                name="Certificate hostname",
                category="TLS",
                status="fail",
                summary="The certificate does not cover this hostname.",
                detail=(
                    ", ".join(dns_names)
                    if dns_names
                    else "No DNS names were found in the certificate."
                ),
            )
        )

    verification_error = _verify_certificate(
        hostname,
        selected_address,
    )

    if verification_error is None:
        results.append(
            CheckResult(
                name="Certificate verification",
                category="TLS",
                status="pass",
                summary="Certificate verification succeeded.",
                detail=(
                    "The certificate chain, hostname, and validity "
                    "were accepted by the scanner."
                ),
            )
        )
    else:
        results.append(
            CheckResult(
                name="Certificate verification",
                category="TLS",
                status="fail",
                summary="Certificate verification failed.",
                detail=verification_error,
            )
        )

    return results
