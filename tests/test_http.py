import pytest

import app.checks.http as http_checks
from app.checks.http import (
    HttpTrace,
    ResponseSnapshot,
    _parse_target,
    check_http,
)
from app.security import TargetValidationError


def test_parse_target_rejects_nonstandard_port():
    with pytest.raises(TargetValidationError):
        _parse_target(
            "https://example.com:8080/"
        )


def test_http_redirect_and_https_success(monkeypatch):
    http_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="http://example.com/",
                address="93.184.216.34",
                status=301,
                reason="Moved Permanently",
                headers={
                    "location": "https://example.com/"
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
    )

    https_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="https://example.com/",
                address="93.184.216.34",
                status=200,
                reason="OK",
                headers={},
            )
        ]
    )

    monkeypatch.setattr(
        http_checks,
        "_follow_redirects",
        lambda url: http_trace,
    )

    results = check_http(
        "example.com",
        ["93.184.216.34"],
        https_trace=https_trace,
    )

    assert len(results) == 3
    assert all(result.status == "pass" for result in results)


def test_http_warns_when_not_redirected(monkeypatch):
    http_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="http://example.com/",
                address="93.184.216.34",
                status=200,
                reason="OK",
                headers={},
            )
        ]
    )

    https_trace = HttpTrace(
        responses=[
            ResponseSnapshot(
                url="https://example.com/",
                address="93.184.216.34",
                status=200,
                reason="OK",
                headers={},
            )
        ]
    )

    monkeypatch.setattr(
        http_checks,
        "_follow_redirects",
        lambda url: http_trace,
    )

    results = check_http(
        "example.com",
        ["93.184.216.34"],
        https_trace=https_trace,
    )

    redirect_result = next(
        result
        for result in results
        if result.name == "HTTP to HTTPS redirect"
    )

    assert redirect_result.status == "warn"
