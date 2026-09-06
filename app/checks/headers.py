from app.checks.http import ResponseSnapshot
from app.models import CheckResult


def check_security_headers(
    response: ResponseSnapshot | None,
) -> list[CheckResult]:
    """Inspect common browser security headers on the final HTTPS response."""

    if response is None:
        return [
            CheckResult(
                name="Security headers",
                category="Security",
                status="fail",
                summary="Security headers could not be inspected.",
                detail="No final HTTPS response was available.",
            )
        ]

    headers = response.headers
    results = []

    checks = [
        (
            "Strict-Transport-Security",
            "HSTS",
            "HSTS tells browsers to use HTTPS for future connections.",
        ),
        (
            "Content-Security-Policy",
            "Content Security Policy",
            "CSP limits which resources a browser may load or execute.",
        ),
        (
            "X-Content-Type-Options",
            "X-Content-Type-Options",
            "This header helps prevent MIME-type sniffing.",
        ),
        (
            "Referrer-Policy",
            "Referrer Policy",
            "Referrer Policy controls how much referral information browsers send.",
        ),
    ]

    for header_name, display_name, explanation in checks:
        value = headers.get(header_name.lower())

        if value:
            results.append(
                CheckResult(
                    name=display_name,
                    category="Security",
                    status="pass",
                    summary=f"{header_name} is configured.",
                    detail=value,
                )
            )
        else:
            results.append(
                CheckResult(
                    name=display_name,
                    category="Security",
                    status="warn",
                    summary=f"{header_name} was not found.",
                    detail=explanation,
                )
            )

    return results
