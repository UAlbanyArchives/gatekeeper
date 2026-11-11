# gatekeeper
A basic Flask wrapper app for implementing Cloudflare Turnstile

## Setup

Configure a Turnstile widget for each challenge hostname, and create a random,
dedicated signing key (for example, generate one with
`python3 -c "import secrets; print(secrets.token_hex(32))"`). Save the same
hexadecimal key in the container environment and in a host-side file.

Create a local `docker-compose.yml`:

```yaml
services:
  turnstile-proxy:
    build: .
    ports:
      - "127.0.0.1:8000:5000"
    restart: always
    environment:
      - LOG_LEVEL=INFO
      - TURNSTILE_SECRET=${TURNSTILE_SECRET:?Set TURNSTILE_SECRET}
      - TURNSTILE_SITEKEY=${TURNSTILE_SITEKEY:?Set TURNSTILE_SITEKEY}
      - SESSION_SIGNING_KEY=${SESSION_SIGNING_KEY:?Set SESSION_SIGNING_KEY}
      - TURNSTILE_ALLOWED_HOSTNAMES=archives.albany.edu,scholars.albany.edu
      - VERIFICATION_LIFETIME=1800
```

Set the secrets in your deployment environment or an untracked `.env` file.
The signing key must be at least 32 random bytes, represented as at least 64
hexadecimal characters. Changing it invalidates all existing sessions. Set
`VERIFICATION_LIFETIME` to the desired lifetime in seconds (default 1800;
valid range 1–86400). The Apache verifier's maximum lifetime must match it.
`TURNSTILE_ALLOWED_HOSTNAMES` is a comma-separated list of exact challenge
hostnames; each must also be authorized in the Cloudflare widget. A successful
Siteverify response must match both the request hostname and this list.

Run `docker compose up -d --build`. The example binds Gatekeeper to localhost
on port 8000; adapt the address if Apache runs on another host, and restrict
access to Gatekeeper to trusted proxies.

## Apache configuration

**The old `turnstile_verified=1` cookie check is not secure.** Deploy the
application and proxy changes together. Merely checking whether the cookie is
present does not enforce verification.

The following adapts the existing rules to Apache with `mod_rewrite` and
host Python. Copy `gatekeeper_cookie.py` and `apache/gatekeeper_map.py` into
`/usr/local/libexec/gatekeeper/`, and make the latter executable. Ensure both
files and their parent directories are writable only by administrators.
Place the hex signing key in `/etc/httpd/gatekeeper.key`, with no other data.
The verifier process below runs as `apache:apache`, so that account must be
able to read the key and traverse its parent directories; grant no other
untrusted users access. For example, use a root-owned key with group `apache`
and mode `0640`. Never commit the key or put it in Apache configuration.

In the existing protected virtual host, retain the application proxy and other
unrelated rules. Adapt this example's hostname, key path, lifetime and existing
whitelist paths; use a separate verifier map for each protected hostname:

```apache
ProxyPass /challenge http://localhost:8000/challenge
ProxyPassReverse /challenge http://localhost:8000/challenge
ProxyPreserveHost On

RewriteEngine On
RewriteMap whitelisted_ips "txt:/opt/whitelisted_ips"
RewriteMap whitelisted_ips_local "txt:/opt/whitelisted_ips_local"
RewriteMap gatekeeper_archive "prg:/usr/local/libexec/gatekeeper/gatekeeper_map.py /etc/httpd/gatekeeper.key archives.albany.edu 1800" apache:apache

# Do not let another Host use this hostname's verifier.
RewriteCond %{HTTP_HOST} !^archives\.albany\.edu(?::443)?$ [NC]
RewriteRule ^ - [F,L]

# Extract only the cookie value for the local verifier.
RewriteRule ^ - [E=GK_COOKIE:-]
RewriteCond %{HTTP:Cookie} "(?:^|;[[:space:]]*)turnstile_verified=([^;[:space:]]+)(?:;|$)"
RewriteRule ^ - [E=GK_COOKIE:%1]

RewriteCond %{REQUEST_METHOD} !=OPTIONS
RewriteCond %{REQUEST_URI} !^/challenge
RewriteCond %{REQUEST_URI} !^/(robots\.txt|favicon\.ico|sitemap\.xml|llms\.txt|google[0-9a-f]+\.html)$
RewriteCond %{REQUEST_URI} !^/description/sitemap(\.xml|(/.*)?$)
RewriteCond ${whitelisted_ips:%{REMOTE_ADDR}|NOT_FOUND} !^ALLOW$
RewriteCond ${whitelisted_ips_local:%{REMOTE_ADDR}|NOT_FOUND} !^ALLOW$
RewriteCond ${gatekeeper_archive:%{ENV:GK_COOKIE}|INVALID} !^VALID$
RewriteRule (.*) /challenge?next=%{REQUEST_URI} [R=302,L,QSA]
```

The map uses a persistent local Python process and returns `VALID` only for
well-formed cookies with a valid hostname-bound HMAC-SHA256 signature and
unexpired timestamp. It sends no requests to Flask. Only the original whitelist,
OPTIONS, and public-path exemptions bypass the check. Apply equivalent rules
to every protected virtual host and verify other rewrites, caching, proxy
routes, and access rules cannot bypass them. Keep the challenge mapping before
application mappings and block direct public access to the upstream.

The wire format is `v1.issued.expiry.nonce.signature`: timestamps are Unix
seconds, nonce is 16 random bytes in lowercase hex, and signature is lowercase
hex HMAC-SHA256 over the ASCII string
`lowercase-hostname|v1.issued.expiry.nonce`. The configured key is decoded
from hex to bytes before HMAC. The verifier rejects timestamps in the future,
expired cookies, and lifetimes longer than its configured maximum.

The cookie is host-only, `Secure`, `HttpOnly`, and `SameSite=Lax`; users verify
separately on each hostname. Flask also deletes the previous `.albany.edu`
cookie after successful verification. Signed cookies can still be copied and
replayed until they expire. Keep host and container clocks synchronized; a
future-issued or expired cookie is rejected. Rotate the key if compromised.

Apache starts one verifier when it starts or restarts; it flushes each
response. Apache serializes worker lookups through its rewrite-map mutex.
This can bottleneck busy sites, and a hung program can block requests; monitor
latency and Apache logs under load. A terminated or misconfigured verifier
must not grant access and requires an Apache restart after correction. Use
`apachectl configtest` and check error logs: configtest alone does not prove
the verifier can read the key under the Apache account or SELinux policy.

With `TRUST_PROXY_IP=true`, Gatekeeper sends the client address from
`X-Forwarded-For` to Cloudflare. Enable this only when all traffic to Gatekeeper
passes through a trusted proxy that **overwrites** that header. If a
load balancer or CDN is in front of Apache, configure `mod_remoteip` to
trust only its documented proxy ranges before using `REMOTE_ADDR`. Otherwise
leave `TRUST_PROXY_IP` unset or false; Gatekeeper then omits the optional IP.
Never expose the upstream application directly to untrusted clients.

Avoid logging cookies, Turnstile tokens, secrets, or sensitive query strings.
Apache rewrite trace logging can expose cookie values; leave it disabled in
normal operation. The application does not impose an IP-based rate limit.

## Migration and verification

1. Generate a new signing key, configure it and the same lifetime on the host
   and in Docker, and copy the verifier files. Ensure `/usr/bin/python3` exists,
   permissions and SELinux allow the Apache account to read the files, and
   `ProxyPreserveHost On` is effective.
2. Deploy Flask and replace the old Apache cookie-presence rule together.
   Existing cookies will not validate; visitors must verify again.
3. Run `sudo httpd -t`, restart Apache to start the map, and inspect its
   error log. Test a non-whitelisted client: no cookie, `turnstile_verified=1`,
   a modified cookie, and an expired cookie must redirect. Complete Turnstile
   and confirm a protected request succeeds until expiration. Confirm a cookie
   from one hostname fails on another, whitelisted clients and public paths
   retain their previous behavior, and original query strings survive.
4. In a non-production test environment, test both a missing or unreadable key
   at startup and a terminated verifier; confirm requests are denied rather than
   passed through. Restore the key and restart Apache.
   Test multiple workers and expected peak load before production rollout.

## Template wrapper configuration

Set `TEMPLATE_WRAPPER` to `archives.html` (the default) or
`scholars_archive.html`. To use a custom wrapper, add a template to
`app/templates/` and set `TEMPLATE_WRAPPER` to its filename. `CONTACT_URL` can
override the wrapper's contact link.

## Tests

Install the requirements and run `python -m unittest discover -s tests`.
