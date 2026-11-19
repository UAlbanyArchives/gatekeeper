# gatekeeper
A basic Flask wrapper app for implementing Cloudflare Turnstile

## Setup

Copy `.env.example` to `.env` and set the Turnstile credentials and signing-key
path for your environment. Keep `.env` and the signing-key file private and out
of version control. Docker Compose reads `.env` for interpolation in the
repository's `docker-compose.yml`.

## Run

```
docker compose build
docker compose up -d
```

Serves on :8000 with above compose file

## Config

### Signed Cookie Settings

The signed-cookie environment settings are listed in `.env.example`:
`GATEKEEPER_KEY_PATH` identifies the host-side key file mounted by Compose,
`GATEKEEPER_HOSTNAME` is the hostname covered by the signature, and
`GATEKEEPER_COOKIE_TTL` sets its lifetime in seconds. The key file must contain
exactly 64 hexadecimal characters (32 bytes when decoded). The example uses a
1800-second TTL and `archives.albany.edu`; use separate private key files for
development and production, and do not commit or log key contents.

### Basic Configuration

Nginx config to proxy to Gatekeeper:
```
location /challenge {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

For things behind Turnstile, place this at the top of the location block:

```
if ($http_cookie !~* "turnstile_verified=1") {
  return 302 /challenge?next=$request_uri;
}
```

### Template Wrapper Configuration

The challenge and failure pages use a configurable wrapper template to support
different styling and branding. Set `TEMPLATE_WRAPPER` in `.env` to
`archives.html` (the default) or `scholars_archive.html`.

To use a custom wrapper, add your template to `app/templates/` (e.g., `myapp.html`) and set `TEMPLATE_WRAPPER=myapp.html`.

## Tests

Install dependencies and run the test suite with coverage:

```
pip install -r requirements.txt
pytest
```

Pytest is configured to measure branch coverage for `app.main` and enforce at
least 95% coverage.
