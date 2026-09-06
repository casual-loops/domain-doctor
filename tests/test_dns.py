from app.checks.dns import check_dns


def test_dns_reports_ipv4_and_ipv6():
    results = check_dns(
        "example.com",
        [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
        ],
    )

    assert len(results) == 3
    assert all(result.status == "pass" for result in results)


def test_dns_warns_when_ipv6_is_missing():
    results = check_dns(
        "example.com",
        ["93.184.216.34"],
    )

    ipv6_result = next(
        result
        for result in results
        if result.name == "IPv6 records"
    )

    assert ipv6_result.status == "warn"
