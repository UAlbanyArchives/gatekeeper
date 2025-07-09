# gatekeeper
A basic Flask wrapper app for implementing Cloudflare Turnstile

## Setup

Create a docker-compose.yml:
```
version: "3.8"

services:
  turnstile-proxy:
    build: .
    ports:
      - "8000:5000"
    environment:
      - LOG_LEVEL=DEBUG
      - TURNSTILE_SECRET=your_turnstile_secret
      - TURNSTILE_SITEKEY=your_turnstile_sitekey
```

## Run

```
docker compose build
docker compose up -d
```

Serves on :8000 with above compose file

## Config

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
