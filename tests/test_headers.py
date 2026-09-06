from app.checks.headers import check_security_headers
from app.checks.http import ResponseSnapshot


def test_security_headers_pass_when_present():
    response = ResponseSnapshot(
        url="https://example.com/",
        address="93.184.216.34",
        status=200,
        reason="OK",
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
        },
    )

    results = check_security_headers(response)

    assert len(results) == 4
    assert all(result.status == "pass" for result in results)


def test_security_headers_warn_when_missing():
    response = ResponseSnapshot(
        url="https://example.com/",
        address="93.184.216.34",
        status=200,
        reason="OK",
        headers={},
    )

    results = check_security_headers(response)

    assert len(results) == 4
    assert all(result.status == "warn" for result in results)


def test_security_headers_fail_without_https_response():
    results = check_security_headers(None)

    assert len(results) == 1
    assert results[0].status == "fail"
