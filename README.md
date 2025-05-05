# gatekeeper
A basic Flask wrapper app for implementing Cloudflare Turnstile

## Setup

```
version: "3.8"

services:
  turnstile-proxy:
    build: .
    ports:
      - "8000:5000"
    environment:
      - TURNSTILE_SECRET=your_turnstile_secret
      - TURNSTILE_SITEKEY=your_turnstile_sitekey
```

## Run

```
docker-compose up --build
```

Serves on :8000
