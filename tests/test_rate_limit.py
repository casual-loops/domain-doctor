from fastapi.testclient import TestClient

import app.main as main
from app.models import CheckResult
from app.rate_limit import SlidingWindowRateLimiter


client = TestClient(main.app)


def fake_results():
    return [
        CheckResult(
            name="DNS resolution",
            category="DNS",
            status="pass",
            summary="Hostname resolves successfully.",
            detail="example.com resolved successfully.",
        )
    ]


def test_sliding_window_blocks_after_limit():
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        max_requests=2,
        window_seconds=60,
        clock=lambda: now[0],
    )

    first = limiter.check("client")
    second = limiter.check("client")
    blocked = limiter.check("client")

    assert first.allowed is True
    assert first.remaining == 1
    assert second.allowed is True
    assert second.remaining == 0
    assert blocked.allowed is False
    assert blocked.retry_after == 60


def test_sliding_window_recovers_after_window():
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
        clock=lambda: now[0],
    )

    assert limiter.check("client").allowed is True
    assert limiter.check("client").allowed is False

    now[0] = 160.0

    assert limiter.check("client").allowed is True


def test_api_check_returns_429_when_rate_limited(monkeypatch):
    limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
    )

    monkeypatch.setattr(main, "api_scan_rate_limiter", limiter)
    monkeypatch.setattr(main, "API_SCAN_RATE_LIMIT", 1)
    monkeypatch.setattr(
        main,
        "diagnose_host",
        lambda host: (
            "example.com",
            fake_results(),
        ),
    )

    first = client.get(
        "/api/check",
        params={"host": "example.com"},
    )
    blocked = client.get(
        "/api/check",
        params={"host": "example.com"},
    )

    assert first.status_code == 200
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"]
    assert blocked.headers["x-ratelimit-limit"] == "1"
    assert blocked.json()["detail"].startswith("Too many diagnostic requests")


def test_report_returns_429_page_when_rate_limited(monkeypatch):
    limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
    )

    monkeypatch.setattr(main, "browser_scan_rate_limiter", limiter)
    monkeypatch.setattr(main, "BROWSER_SCAN_RATE_LIMIT", 1)
    monkeypatch.setattr(
        main,
        "diagnose_host",
        lambda host: (
            "example.com",
            fake_results(),
        ),
    )

    first = client.get(
        "/check",
        params={"host": "example.com"},
    )
    blocked = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert first.status_code == 200
    assert blocked.status_code == 429
    assert "Too many diagnostic requests" in blocked.text
    assert blocked.headers["retry-after"]
    assert blocked.headers["x-ratelimit-limit"] == "1"


def test_browser_and_api_limits_use_separate_buckets(monkeypatch):
    api_limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
    )
    browser_limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
    )

    monkeypatch.setattr(main, "api_scan_rate_limiter", api_limiter)
    monkeypatch.setattr(main, "browser_scan_rate_limiter", browser_limiter)
    monkeypatch.setattr(main, "API_SCAN_RATE_LIMIT", 1)
    monkeypatch.setattr(main, "BROWSER_SCAN_RATE_LIMIT", 1)
    monkeypatch.setattr(
        main,
        "diagnose_host",
        lambda host: (
            "example.com",
            fake_results(),
        ),
    )

    api_first = client.get(
        "/api/check",
        params={"host": "example.com"},
    )
    api_blocked = client.get(
        "/api/check",
        params={"host": "example.com"},
    )
    browser_first = client.get(
        "/check",
        params={"host": "example.com"},
    )

    assert api_first.status_code == 200
    assert api_blocked.status_code == 429
    assert browser_first.status_code == 200
