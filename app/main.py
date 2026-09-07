import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.checks.dns import check_dns
from app.checks.headers import check_security_headers
from app.checks.http import check_http, inspect_https
from app.checks.tls import check_tls
from app.rate_limit import SlidingWindowRateLimiter, get_client_identifier
from app.security import TargetValidationError, validate_target


SCAN_RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "30"))
SCAN_RATE_WINDOW_SECONDS = int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "60"))

scan_rate_limiter = SlidingWindowRateLimiter(
    max_requests=SCAN_RATE_LIMIT,
    window_seconds=SCAN_RATE_WINDOW_SECONDS,
)


app = FastAPI(
    title="Domain Doctor",
    version="1.0.0",
    description="Outside-in health checks for public domains and web services.",
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)

templates = Jinja2Templates(
    directory="app/templates",
)


def diagnose_host(host: str):
    """
    Run all Domain Doctor diagnostics for a public hostname.
    """

    hostname, addresses = validate_target(host)

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

    return hostname, results


def enforce_scan_rate_limit(request: Request):
    client_identifier = get_client_identifier(request)
    decision = scan_rate_limiter.check(client_identifier)

    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many diagnostic requests. "
                "Please wait before running another check."
            ),
            headers={
                "Retry-After": str(decision.retry_after),
                "X-RateLimit-Limit": str(SCAN_RATE_LIMIT),
                "X-RateLimit-Remaining": "0",
            },
        )

    return decision


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
    )


@app.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="privacy.html",
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "1.0.0",
    }


@app.get("/check", response_class=HTMLResponse)
def check_page(
    request: Request,
    host: str = Query(...),
):
    try:
        enforce_scan_rate_limit(request)
        hostname, results = diagnose_host(host)

    except HTTPException as exc:
        if exc.status_code != 429:
            raise

        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={
                "hostname": host,
                "error": exc.detail,
            },
            status_code=429,
            headers=exc.headers,
        )

    except TargetValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={
                "hostname": host,
                "error": str(exc),
            },
            status_code=400,
        )

    grouped_results = {}

    for result in results:
        grouped_results.setdefault(
            result.category,
            [],
        ).append(result)

    counts = {
        "pass": sum(
            result.status == "pass"
            for result in results
        ),
        "warn": sum(
            result.status == "warn"
            for result in results
        ),
        "fail": sum(
            result.status == "fail"
            for result in results
        ),
    }

    category_counts = {}

    for category, category_results in grouped_results.items():
        category_counts[category] = {
            "pass": sum(
                result.status == "pass"
                for result in category_results
            ),
            "warn": sum(
                result.status == "warn"
                for result in category_results
            ),
            "fail": sum(
                result.status == "fail"
                for result in category_results
            ),
        }

    if counts["fail"] > 0:
        overall_status = "ISSUES DETECTED"
        overall_class = "issues"
        overall_summary = (
            "One or more checks failed and should be reviewed."
        )

    elif counts["warn"] > 0:
        overall_status = "ATTENTION"
        overall_class = "attention"
        overall_summary = (
            "No critical failures were detected, but some "
            "configuration items may deserve review."
        )

    else:
        overall_status = "HEALTHY"
        overall_class = "healthy"
        overall_summary = (
            "No configuration problems were detected by the "
            "current diagnostic checks."
        )

    checked_at = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "hostname": hostname,
            "grouped_results": grouped_results,
            "counts": counts,
            "category_counts": category_counts,
            "overall_status": overall_status,
            "overall_class": overall_class,
            "overall_summary": overall_summary,
            "checked_at": checked_at,
            "error": None,
        },
    )


@app.get("/api/check")
def check_domain(
    request: Request,
    host: str = Query(
        ...,
        description="Public hostname to inspect, such as example.com",
    ),
):
    enforce_scan_rate_limit(request)

    try:
        hostname, results = diagnose_host(host)

    except TargetValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "hostname": hostname,
        "results": results,
    }
