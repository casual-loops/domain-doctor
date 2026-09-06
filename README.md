# Domain Doctor

[![Tests](https://github.com/casual-loops/domain-doctor/actions/workflows/test.yml/badge.svg)](https://github.com/casual-loops/domain-doctor/actions/workflows/test.yml)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Know what the internet sees.**

Domain Doctor is an open-source, outside-in diagnostic tool for inspecting the public-facing health of a hostname.

Enter one public hostname and Domain Doctor checks DNS resolution, TLS certificates, HTTPS behavior, redirects, and common browser security headers.

No account is required.

## What it checks

| Category | Diagnostics |
| --- | --- |
| DNS | Resolution, IPv4 records, IPv6 records |
| TLS | TLS connectivity, certificate validity, expiration, hostname coverage, certificate verification |
| HTTP | HTTP reachability, HTTP to HTTPS redirects, final HTTPS response |
| Security | HSTS, Content Security Policy, X-Content-Type-Options, Referrer Policy |

Every diagnostic returns one of three states:

| State | Meaning |
| --- | --- |
| PASS | The check completed successfully |
| WARN | The result may deserve review, but does not necessarily indicate a broken service |
| FAIL | The check detected a problem or could not complete safely |

## Interface

Domain Doctor includes a responsive browser interface with light and dark themes, report navigation, status filtering, expandable technical details, and an overall diagnostic verdict.

### Landing page

![Domain Doctor landing page](docs/images/landing.png)

### Diagnostic report

![Domain Doctor diagnostic report](docs/images/report.png)

The same diagnostic engine is also available through a JSON API.

## API

Check a public hostname:

```text
GET /api/check?host=example.com
```

Example response:

```json
{
  "hostname": "example.com",
  "results": [
    {
      "name": "DNS resolution",
      "category": "DNS",
      "status": "pass",
      "summary": "Hostname resolves successfully.",
      "detail": "example.com resolved to public addresses."
    }
  ]
}
```

Interactive OpenAPI documentation is available at:

```text
/docs
```

## Security model

Domain Doctor accepts hostnames that cause the server to make outbound network connections, so target validation is part of the application design rather than an afterthought.

The current protections include:

1. IP address literals are rejected.
2. Private, loopback, link-local, reserved, and other non-public addresses are rejected.
3. HTTP and HTTPS are the only permitted protocols.
4. Network connections are restricted to ports 80 and 443.
5. Redirect destinations are validated before they are followed.
6. TLS and HTTP connections are pinned to previously validated public IP addresses.
7. Redirect depth and network timeouts are limited.
8. The production container runs as a non-root user.
9. The Compose configuration drops Linux capabilities and enables `no-new-privileges`.

These controls reduce SSRF risk, but Domain Doctor should still be deployed as an Internet-facing service using defense-in-depth controls such as firewalling, rate limiting, logging, and isolation from private infrastructure.

## Run with Docker Compose

Clone the repository:

```bash
git clone git@github.com:casual-loops/domain-doctor.git
cd domain-doctor
```

Start the application:

```bash
docker compose up -d --build
```

Check container health:

```bash
docker compose ps
```

By default, the development Compose stack exposes Domain Doctor on:

```text
http://localhost:8001
```

Stop it with:

```bash
docker compose down
```

## Run with Python

Python 3.13 is the current development target.

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment, then install dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Start the development server:

```bash
python -m uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Tests

The test suite avoids depending on live Internet services for automated checks. Network behavior is mocked where appropriate so CI results remain deterministic.

Run the suite with:

```bash
python -m pytest -v
```

GitHub Actions runs the same suite on pushes and pull requests to `main`.

## Project structure

```text
domain-doctor/
├── app/
│   ├── checks/
│   │   ├── dns.py
│   │   ├── headers.py
│   │   ├── http.py
│   │   └── tls.py
│   ├── static/
│   ├── templates/
│   ├── main.py
│   ├── models.py
│   └── security.py
├── tests/
├── .github/
│   └── workflows/
│       └── test.yml
├── Dockerfile
├── compose.yaml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Current scope

Domain Doctor v1 focuses on public web service diagnostics.

It does not currently provide continuous monitoring, historical uptime, account management, email DNS analysis, or multi-resolver DNS comparison.

Those capabilities may be considered for future releases rather than expanding the initial release scope.

## License

Domain Doctor is released under the MIT License.

## Author

Built by [casual-loops](https://github.com/casual-loops).
