# Production Deployment

Domain Doctor production runs separately from the development environment and consumes versioned container images published to GitHub Container Registry.

## Current architecture

```text
Internet
  ↓
domaindoctor.fyi
  ↓
Cloud firewall
  ↓
Caddy with automatic TLS
  ↓
Domain Doctor container bound to localhost
```

The application container is exposed only on the loopback interface and is reached through Caddy.

Example production binding:

```text
127.0.0.1:8000:8000
```

## Container release flow

The GitHub Actions publishing workflow produces two kinds of images.

Pushes to `main` publish:

```text
ghcr.io/casual-loops/domain-doctor:main
ghcr.io/casual-loops/domain-doctor:sha-<commit>
```

Version tags publish:

```text
ghcr.io/casual-loops/domain-doctor:<version>
ghcr.io/casual-loops/domain-doctor:latest
```

Production should remain pinned to a versioned image rather than the moving `main` or `latest` tags.

Example:

```yaml
services:
  app:
    image: ghcr.io/casual-loops/domain-doctor:1.1.0
```

## Deployment procedure

After a version tag has been pushed and the Publish Container workflow has completed successfully:

```bash
cd /opt/domain-doctor
sudo cp compose.yaml compose.yaml.bak-<previous-version>
```

Update the image tag in `compose.yaml`, then pull and recreate only the application service:

```bash
sudo docker compose pull app
sudo docker compose up -d app
```

Verify the deployment:

```bash
sudo docker compose ps
curl -s http://127.0.0.1:8000/health
sudo docker ps --format 'table {{.Names}}\t{{.Image}}'
```

The health endpoint should report the expected application version.

## Caddy and Content Security Policy

Domain Doctor loads Umami Cloud analytics only on the production hostname. A restrictive Content Security Policy must explicitly allow the Umami script and analytics gateway.

The production policy requires these origins:

```text
script-src:
https://cloud.umami.is

connect-src:
https://cloud.umami.is
https://gateway.umami.is
```

A compatible policy includes directives similar to:

```text
script-src 'self' https://cdn.jsdelivr.net https://cloud.umami.is;
connect-src 'self' https://cloud.umami.is https://gateway.umami.is;
```

Keep the rest of the existing Content Security Policy intact. Do not replace the policy with a permissive wildcard solely to enable analytics.

### Swagger UI exception

FastAPI serves Swagger UI at `/docs`. Swagger initializes with an inline script, so the stricter site-wide CSP will leave `/docs` blank unless that route receives a narrower exception.

Keep the global application CSP unchanged and apply the exception only to the documentation route:

```caddy
@docs path /docs /docs/*

header @docs >Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
```

This permits the inline Swagger initialization script only for `/docs` while preserving the stricter policy on the rest of Domain Doctor.

Before applying a Caddy configuration change, validate it:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
```

Then reload Caddy without restarting the application container:

```bash
sudo systemctl reload caddy
```

## Production validation

After deployment, verify all of the following:

1. The homepage loads over HTTPS.
2. `/health` reports the expected version.
3. A normal public hostname diagnostic completes successfully.
4. `/privacy` loads correctly.
5. The Feedback link opens the GitHub feedback form.
6. Browser and API rate limiting still behave as expected.
7. Browser developer tools show the Umami script loading from `cloud.umami.is`.
8. Analytics requests to `gateway.umami.is/api/send` are not blocked by Content Security Policy.
9. Umami receives a production visit.
10. `/docs` renders the FastAPI Swagger UI successfully.

## Rollback

If the new application version fails validation, restore the previous versioned image in `compose.yaml` and recreate the application service:

```bash
sudo docker compose pull app
sudo docker compose up -d app
```

If a Caddy configuration change causes a problem, restore the previous Caddyfile backup, validate it, and reload Caddy.
