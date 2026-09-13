import pytest

import app.checks.http as http_checks
from app.checks.http import (
    HttpTrace,
    ResponseSnapshot,
    _follow_redirects,
    _parse_target,
    check_http,
    _request_once,
)
from app.security import TargetValidationError, ValidatedTarget


def snapshot(
    url: str,
    status: int = 200,
    reason: str = "OK",
    location: str | None = None,
) -> ResponseSnapshot:
    headers = {}

    if location is not None:
        headers["location"] = location

    return ResponseSnapshot(
        url=url,
        address="93.184.216.34",
        status=status,
        reason=reason,
        headers=headers,
    )


def test_parse_target_rejects_nonstandard_port():
    with pytest.raises(TargetValidationError):
        _parse_target(
            "https://example.com:8080/"
        )


def test_trace_final_returns_last_response():
    trace = HttpTrace(
        responses=[
            snapshot(
                "http://example.com/",
                status=301,
                reason="Moved Permanently",
                location="https://example.com/",
            ),
            snapshot("https://example.com/"),
        ]
    )

    final = trace.final

    assert final is not None
    assert final is trace.responses[-1]
    assert final.url == "https://example.com/"


def test_follow_redirects_without_redirect(monkeypatch):
    calls = []

    def fake_request(url):
        calls.append(url)
        return snapshot(url)

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "https://example.com/"
    )

    final = trace.final

    assert trace.error is None
    assert len(trace.responses) == 1
    assert final is not None
    assert final.url == "https://example.com/"
    assert calls == ["https://example.com/"]


def test_follow_redirects_single_http_to_https_redirect(monkeypatch):
    calls = []

    def fake_request(url):
        calls.append(url)

        if url == "http://example.com/":
            return snapshot(
                url,
                status=301,
                reason="Moved Permanently",
                location="https://example.com/",
            )

        return snapshot(url)

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "http://example.com/"
    )

    final = trace.final

    assert trace.error is None
    assert [response.status for response in trace.responses] == [301, 200]
    assert final is not None
    assert final.url == "https://example.com/"
    assert calls == [
        "http://example.com/",
        "https://example.com/",
    ]


def test_follow_redirects_multiple_hops_and_hostname_change(monkeypatch):
    calls = []

    def fake_request(url):
        calls.append(url)

        if url == "http://example.com/":
            return snapshot(
                url,
                status=301,
                reason="Moved Permanently",
                location="https://example.com/",
            )

        if url == "https://example.com/":
            return snapshot(
                url,
                status=302,
                reason="Found",
                location="https://www.example.net/final",
            )

        return snapshot(url)

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "http://example.com/"
    )

    final = trace.final

    assert trace.error is None
    assert [response.status for response in trace.responses] == [
        301,
        302,
        200,
    ]
    assert final is not None
    assert final.url == "https://www.example.net/final"
    assert calls == [
        "http://example.com/",
        "https://example.com/",
        "https://www.example.net/final",
    ]


def test_follow_redirects_records_unsafe_target_error(monkeypatch):
    def fake_request(url):
        if url == "http://127.0.0.1/":
            raise TargetValidationError(
                "IP address literals are not allowed."
            )

        return snapshot(
            url,
            status=302,
            reason="Found",
            location="http://127.0.0.1/",
        )

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "http://example.com/"
    )

    final = trace.final

    assert len(trace.responses) == 1
    assert final is not None
    assert final.url == "http://example.com/"
    assert trace.error is not None
    assert trace.error.startswith("Target rejected:")
    assert "not allowed" in trace.error


def test_follow_redirects_enforces_redirect_limit(monkeypatch):
    def fake_request(url):
        return snapshot(
            url,
            status=302,
            reason="Found",
            location="/next",
        )

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "http://example.com/"
    )

    assert len(trace.responses) == http_checks._MAX_REDIRECTS + 1
    assert trace.error == (
        f"Redirect limit of {http_checks._MAX_REDIRECTS} "
        "was exceeded."
    )


def test_follow_redirects_preserves_address_family(monkeypatch):
    calls = []

    def fake_request(url, address_family=None):
        calls.append((url, address_family))

        if url == "http://example.com/":
            return snapshot(
                url,
                status=301,
                reason="Moved Permanently",
                location="https://www.example.com/",
            )

        return snapshot(url)

    monkeypatch.setattr(
        http_checks,
        "_request_once",
        fake_request,
    )

    trace = _follow_redirects(
        "http://example.com/",
        address_family="ipv6",
    )

    final = trace.final

    assert trace.error is None
    assert final is not None
    assert final.url == "https://www.example.com/"
    assert calls == [
        ("http://example.com/", "ipv6"),
        ("https://www.example.com/", "ipv6"),
    ]


def test_http_redirect_and_https_success():
    http_trace = HttpTrace(
        responses=[
            snapshot(
                "http://example.com/",
                status=301,
                reason="Moved Permanently",
                location="https://example.com/",
            ),
            snapshot("https://example.com/"),
        ]
    )

    https_trace = HttpTrace(
        responses=[
            snapshot("https://example.com/")
        ]
    )

    results = check_http(
        "example.com",
        ["93.184.216.34"],
        http_trace=http_trace,
        https_trace=https_trace,
    )

    assert len(results) == 3
    assert all(result.status == "pass" for result in results)


def test_http_warns_when_not_redirected():
    http_trace = HttpTrace(
        responses=[
            snapshot("http://example.com/")
        ]
    )

    https_trace = HttpTrace(
        responses=[
            snapshot("https://example.com/")
        ]
    )

    results = check_http(
        "example.com",
        ["93.184.216.34"],
        http_trace=http_trace,
        https_trace=https_trace,
    )

    redirect_result = next(
        result
        for result in results
        if result.name == "HTTP to HTTPS redirect"
    )

    assert redirect_result.status == "warn"


def test_http_fails_when_redirect_chain_has_error():
    http_trace = HttpTrace(
        responses=[
            snapshot(
                "http://example.com/",
                status=301,
                reason="Moved Permanently",
                location="https://example.com/",
            )
        ],
        error="Redirect limit of 5 was exceeded.",
    )

    https_trace = HttpTrace(
        responses=[
            snapshot("https://example.com/")
        ]
    )

    results = check_http(
        "example.com",
        ["93.184.216.34"],
        http_trace=http_trace,
        https_trace=https_trace,
    )

    redirect_result = next(
        result
        for result in results
        if result.name == "HTTP to HTTPS redirect"
    )

    assert redirect_result.status == "fail"
    assert "could not be completed safely" in redirect_result.summary


def test_request_once_selects_ipv6_address(monkeypatch):
    connected_addresses = []

    class FakeResponse:
        status = 200
        reason = "OK"

        def getheaders(self):
            return []

    class FakeConnection:
        def __init__(
            self,
            hostname,
            address,
            port,
            timeout,
        ):
            connected_addresses.append(address)

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        http_checks,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
        ),
    )

    monkeypatch.setattr(
        http_checks,
        "_PinnedHTTPConnection",
        FakeConnection,
    )

    response = _request_once(
        "http://example.com/",
        address_family="ipv6",
    )

    assert response.address == (
        "2606:2800:220:1:248:1893:25c8:1946"
    )
    assert connected_addresses == [
        "2606:2800:220:1:248:1893:25c8:1946"
    ]


def test_request_once_selects_ipv4_address(monkeypatch):
    connected_addresses = []

    class FakeResponse:
        status = 200
        reason = "OK"

        def getheaders(self):
            return []

    class FakeConnection:
        def __init__(
            self,
            hostname,
            address,
            port,
            timeout,
        ):
            connected_addresses.append(address)

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        http_checks,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(
                "2606:2800:220:1:248:1893:25c8:1946",
            ),
        ),
    )

    monkeypatch.setattr(
        http_checks,
        "_PinnedHTTPConnection",
        FakeConnection,
    )

    response = _request_once(
        "http://example.com/",
        address_family="ipv4",
    )

    assert response.address == "93.184.216.34"
    assert connected_addresses == [
        "93.184.216.34"
    ]


def test_request_once_fails_when_requested_family_is_unavailable(
    monkeypatch,
):
    monkeypatch.setattr(
        http_checks,
        "resolve_target",
        lambda hostname: ValidatedTarget(
            hostname="example.com",
            ipv4_addresses=("93.184.216.34",),
            ipv6_addresses=(),
        ),
    )

    with pytest.raises(
        OSError,
        match="No validated IPv6 address is available",
    ):
        _request_once(
            "http://example.com/",
            address_family="ipv6",
        )