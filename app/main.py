from fastapi import FastAPI, HTTPException, Query

from app.checks.dns import check_dns
from app.checks.headers import check_security_headers
from app.checks.http import check_http, inspect_https
from app.checks.tls import check_tls
from app.security import TargetValidationError, validate_target


app = FastAPI(
    title="Domain Doctor",
    version="0.1.0",
    description="Outside-in health checks for public domains and web services.",
)


@app.get("/")
def root():
    return {
        "name": "Domain Doctor",
        "status": "ok",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/check")
def check_domain(
    host: str = Query(
        ...,
        description="Public hostname to inspect, such as example.com",
    ),
):
    try:
        hostname, addresses = validate_target(host)
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    results = []

    results.extend(
        check_dns(
            hostname,
            addresses,
        )
    )

    results.extend(
        check_tls(
            hostname,
            addresses,
        )
    )

    https_trace = inspect_https(hostname)

    results.extend(
        check_http(
            hostname,
            addresses,
            https_trace=https_trace,
        )
    )

    results.extend(
        check_security_headers(
            https_trace.final,
        )
    )

    return {
        "hostname": hostname,
        "results": results,
    }
