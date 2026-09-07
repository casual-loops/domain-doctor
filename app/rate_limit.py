from collections import defaultdict, deque
from dataclasses import dataclass
from ipaddress import ip_address
from math import ceil
from threading import Lock
from time import monotonic
from typing import Callable

from fastapi.requests import Request


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: int


class SlidingWindowRateLimiter:
    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
    ):
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")

        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._requests = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> RateLimitDecision:
        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._requests[key]

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(
                    1,
                    ceil(self.window_seconds - (now - bucket[0])),
                )

                return RateLimitDecision(
                    allowed=False,
                    remaining=0,
                    retry_after=retry_after,
                )

            bucket.append(now)

            return RateLimitDecision(
                allowed=True,
                remaining=self.max_requests - len(bucket),
                retry_after=0,
            )


def _normalize_ip(value: str | None) -> str | None:
    if not value:
        return None

    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def get_client_identifier(request: Request) -> str:
    """
    Return the best available client IP for rate limiting.

    Caddy sanitizes X-Forwarded-For by default before proxying requests.
    Domain Doctor only considers that header when the immediate peer is a
    private or loopback address, which matches the production reverse-proxy
    deployment while avoiding trust in forwarded headers from public peers.
    """

    peer = request.client.host if request.client else None
    normalized_peer = _normalize_ip(peer)

    if normalized_peer:
        peer_address = ip_address(normalized_peer)

        if peer_address.is_private or peer_address.is_loopback:
            forwarded_for = request.headers.get("x-forwarded-for")

            if forwarded_for:
                forwarded_client = _normalize_ip(
                    forwarded_for.split(",", 1)[0]
                )

                if forwarded_client:
                    return forwarded_client

        return normalized_peer

    return peer or "unknown"
