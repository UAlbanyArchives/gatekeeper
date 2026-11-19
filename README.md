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

### Apache Deployment

The Apache host validates `gatekeeper_verified` locally with a persistent
Python `RewriteMap prg:` process. It does not call Flask for protected requests.
Apache needs `mod_rewrite`, `mod_proxy`, and `mod_proxy_http` enabled, plus
Python 3.6.8 or newer at `/usr/bin/python3`. The verifier uses only Python's
standard library.

#### Share the signing key

Generate one random key file on the Apache host. The same file is mounted
read-only into Flask by Docker Compose:

```sh
sudo install -d -o root -g apache -m 0750 /etc/httpd
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/httpd/gatekeeper.key'
sudo chown root:apache /etc/httpd/gatekeeper.key
sudo chmod 0640 /etc/httpd/gatekeeper.key
```

Set `GATEKEEPER_KEY_PATH=/etc/httpd/gatekeeper.key` in the untracked `.env`
file used by Compose. Apache and Flask must read this same key. Verify that
the `apache` account can read it and that SELinux policy allows access.
Use separate key files for development and production; never paste the key
into Apache configuration or commit it.

#### Install the verifier

Copy `apache/gatekeeper_map.py` from this repository to a root-owned location
on the host. For example:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/gatekeeper
sudo install -o root -g root -m 0755 apache/gatekeeper_map.py /usr/local/libexec/gatekeeper/gatekeeper_map.py
```

The script is self-contained and does not need the Flask application files or
any Python packages. Test that the Apache service account can start it and
read the key before changing the virtual-host configuration:

```sh
sudo -u apache /usr/bin/python3 \
  /usr/local/libexec/gatekeeper/gatekeeper_map.py \
  /etc/httpd/gatekeeper.key archives.albany.edu 1800 </dev/null
```

For a valid key and arguments the process exits successfully without output
when stdin is closed. Configuration errors are written to stderr; do not enable
Apache rewrite trace logging in production because it can disclose request
details.

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
