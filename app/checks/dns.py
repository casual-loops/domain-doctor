import ipaddress

from app.models import CheckResult


def check_dns(hostname: str, addresses: list[str]) -> list[CheckResult]:
    """Build DNS health results from a validated hostname and its addresses."""

    ipv4_addresses = []
    ipv6_addresses = []

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if ip.version == 4:
            ipv4_addresses.append(address)
        else:
            ipv6_addresses.append(address)

    results = [
        CheckResult(
            name="DNS resolution",
            category="DNS",
            status="pass",
            summary="Hostname resolves successfully.",
            detail=f"{hostname} resolved to {len(addresses)} public address(es).",
        )
    ]

    if ipv4_addresses:
        results.append(
            CheckResult(
                name="IPv4 records",
                category="DNS",
                status="pass",
                summary="IPv4 connectivity is advertised.",
                detail=", ".join(ipv4_addresses),
            )
        )
    else:
        results.append(
            CheckResult(
                name="IPv4 records",
                category="DNS",
                status="warn",
                summary="No IPv4 address was found.",
                detail="The service may only be reachable over IPv6.",
            )
        )

    if ipv6_addresses:
        results.append(
            CheckResult(
                name="IPv6 records",
                category="DNS",
                status="pass",
                summary="IPv6 connectivity is advertised.",
                detail=", ".join(ipv6_addresses),
            )
        )
    else:
        results.append(
            CheckResult(
                name="IPv6 records",
                category="DNS",
                status="warn",
                summary="No IPv6 address was found.",
                detail="IPv6 support is optional, but this service currently advertises IPv4 only.",
            )
        )

    return results
