import http.client
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from app.models import CheckResult
from app.security import TargetValidationError, validate_target


_TIMEOUT_SECONDS = 5
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class ResponseSnapshot:
    url: str
    address: str
    status: int
    reason: str
    headers: dict[str, str]


@dataclass(frozen=True)
class HttpTrace:
    responses: list[ResponseSnapshot]
    error: str | None = None

    @property
    def final(self) -> ResponseSnapshot | None:
        if not self.responses:
            return None

        return self.responses[-1]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """
    HTTP connection that sends the requested hostname in the Host header
    while connecting directly to an already validated IP address.
    """

    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        timeout: int,
    ):
        super().__init__(
            host=hostname,
            port=port,
            timeout=timeout,
        )
        self._validated_address = address

    def connect(self):
        self.sock = socket.create_connection(
            (self._validated_address, self.port),
            timeout=self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPS connection pinned to a validated IP address.

    TLS still uses the requested hostname for SNI and certificate
    verification.
    """

    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        timeout: int,
    ):
        super().__init__(
            host=hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._validated_address = address

    def connect(self):
        raw_socket = socket.create_connection(
            (self._validated_address, self.port),
            timeout=self.timeout,
        )

        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


def _parse_target(url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError(
            "Redirects may only use HTTP or HTTPS."
        )

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "Redirect targets containing credentials are not allowed."
        )

    if parsed.hostname is None:
        raise TargetValidationError(
            "The redirect target does not contain a hostname."
        )

    try:
        requested_port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(
            "The redirect target contains an invalid port."
        ) from exc

    default_port = 443 if parsed.scheme == "https" else 80
    port = requested_port or default_port

    if port not in {80, 443}:
        raise TargetValidationError(
            f"Redirects to port {port} are not allowed."
        )

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    return parsed.scheme, parsed.hostname, port, path


def _request_once(url: str) -> ResponseSnapshot:
    scheme, hostname, port, path = _parse_target(url)

    normalized_hostname, addresses = validate_target(hostname)

    errors = []

    for address in addresses:
        connection = None

        try:
            if scheme == "https":
                connection = _PinnedHTTPSConnection(
                    normalized_hostname,
                    address,
                    port,
                    _TIMEOUT_SECONDS,
                )
            else:
                connection = _PinnedHTTPConnection(
                    normalized_hostname,
                    address,
                    port,
                    _TIMEOUT_SECONDS,
                )

            connection.request(
                "GET",
                path,
                headers={
                    "Host": normalized_hostname,
                    "User-Agent": "Domain-Doctor/0.1",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )

            response = connection.getresponse()

            headers = {
                name.lower(): value
                for name, value in response.getheaders()
            }

            return ResponseSnapshot(
                url=url,
                address=address,
                status=response.status,
                reason=response.reason,
                headers=headers,
            )

        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as exc:
            errors.append(f"{address}: {exc}")

        finally:
            if connection is not None:
                connection.close()

    raise OSError(
        "; ".join(errors)
        if errors
        else "No validated address could be reached."
    )


def _follow_redirects(start_url: str) -> HttpTrace:
    responses = []
    current_url = start_url

    for redirect_number in range(_MAX_REDIRECTS + 1):
        try:
            response = _request_once(current_url)

        except TargetValidationError as exc:
            return HttpTrace(
                responses=responses,
                error=f"Target rejected: {exc}",
            )

        except OSError as exc:
            return HttpTrace(
                responses=responses,
                error=str(exc),
            )

        responses.append(response)

        location = response.headers.get("location")

        if (
            response.status not in _REDIRECT_STATUSES
            or not location
        ):
            return HttpTrace(responses=responses)

        if redirect_number >= _MAX_REDIRECTS:
            return HttpTrace(
                responses=responses,
                error=(
                    f"Redirect limit of {_MAX_REDIRECTS} "
                    "was exceeded."
                ),
            )

        current_url = urljoin(current_url, location)

    return HttpTrace(
        responses=responses,
        error="Redirect processing stopped unexpectedly.",
    )


def _trace_detail(trace: HttpTrace) -> str:
    if not trace.responses:
        return trace.error or "No HTTP response was received."

    parts = []

    for response in trace.responses:
        parts.append(
            f"{response.status} {response.url}"
        )

    detail = " -> ".join(parts)

    if trace.error:
        detail = f"{detail}. {trace.error}"

    return detail


def check_http(
    hostname: str,
    addresses: list[str],
) -> list[CheckResult]:
    """
    Check HTTP reachability, HTTPS redirection, and final HTTPS response.

    The addresses argument is retained as part of the checker contract.
    Every network request independently validates and pins its destination
    before connecting.
    """

    del addresses

    results = []

    http_trace = _follow_redirects(
        f"http://{hostname}/"
    )

    if http_trace.responses:
        first_http = http_trace.responses[0]

        results.append(
            CheckResult(
                name="HTTP reachability",
                category="HTTP",
                status="pass",
                summary=(
                    f"HTTP responded with status "
                    f"{first_http.status}."
                ),
                detail=(
                    f"Connected to {first_http.address}."
                ),
            )
        )

        final_http = http_trace.final

        redirected_to_https = (
            final_http is not None
            and urlsplit(final_http.url).scheme == "https"
        )

        if http_trace.error:
            results.append(
                CheckResult(
                    name="HTTP to HTTPS redirect",
                    category="HTTP",
                    status="fail",
                    summary=(
                        "The HTTP redirect chain could not be "
                        "completed safely."
                    ),
                    detail=_trace_detail(http_trace),
                )
            )

        elif redirected_to_https:
            results.append(
                CheckResult(
                    name="HTTP to HTTPS redirect",
                    category="HTTP",
                    status="pass",
                    summary="HTTP redirects to HTTPS.",
                    detail=_trace_detail(http_trace),
                )
            )

        else:
            results.append(
                CheckResult(
                    name="HTTP to HTTPS redirect",
                    category="HTTP",
                    status="warn",
                    summary=(
                        "HTTP does not redirect to HTTPS."
                    ),
                    detail=_trace_detail(http_trace),
                )
            )

    else:
        results.append(
            CheckResult(
                name="HTTP reachability",
                category="HTTP",
                status="warn",
                summary="No HTTP response was received.",
                detail=http_trace.error,
            )
        )

        results.append(
            CheckResult(
                name="HTTP to HTTPS redirect",
                category="HTTP",
                status="warn",
                summary=(
                    "An HTTP to HTTPS redirect could not be verified."
                ),
                detail=http_trace.error,
            )
        )

    https_trace = _follow_redirects(
        f"https://{hostname}/"
    )

    final_https = https_trace.final

    if final_https is None:
        results.append(
            CheckResult(
                name="HTTPS response",
                category="HTTP",
                status="fail",
                summary="No HTTPS response was received.",
                detail=https_trace.error,
            )
        )

        return results

    if https_trace.error:
        https_status = "fail"
        https_summary = (
            "HTTPS responded, but the redirect chain "
            "could not be completed safely."
        )

    elif 200 <= final_https.status < 400:
        https_status = "pass"
        https_summary = (
            f"HTTPS returned status {final_https.status}."
        )

    elif 400 <= final_https.status < 500:
        https_status = "warn"
        https_summary = (
            f"HTTPS returned client status "
            f"{final_https.status}."
        )

    else:
        https_status = "fail"
        https_summary = (
            f"HTTPS returned server status "
            f"{final_https.status}."
        )

    results.append(
        CheckResult(
            name="HTTPS response",
            category="HTTP",
            status=https_status,
            summary=https_summary,
            detail=_trace_detail(https_trace),
        )
    )

    return results
