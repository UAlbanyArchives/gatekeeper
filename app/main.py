import logging
import os
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlsplit, urlunsplit

import requests
from flask import Flask, make_response, redirect, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from gatekeeper_cookie import (
    COOKIE_NAME,
    DEFAULT_LIFETIME,
    issue_cookie,
    parse_key,
    parse_lifetime,
    validate_cookie,
)

app = Flask(
    __name__,
    static_url_path="/challenge/static",
    static_folder="static",
)

TURNSTILE_SECRET = os.environ["TURNSTILE_SECRET"]
TURNSTILE_SITEKEY = os.environ["TURNSTILE_SITEKEY"]
SESSION_SIGNING_KEY = parse_key(os.environ["SESSION_SIGNING_KEY"])
VERIFICATION_LIFETIME = parse_lifetime(
    os.environ.get("VERIFICATION_LIFETIME", str(DEFAULT_LIFETIME))
)

ALLOWED_HOSTNAMES = {
    hostname.strip().lower()
    for hostname in os.environ["TURNSTILE_ALLOWED_HOSTNAMES"].split(",")
    if hostname.strip()
}
if not ALLOWED_HOSTNAMES:
    raise ValueError("TURNSTILE_ALLOWED_HOSTNAMES must not be empty")

TRUST_PROXY_IP = os.environ.get("TRUST_PROXY_IP", "false").lower() == "true"
if TRUST_PROXY_IP:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()
TEMPLATE_WRAPPER = os.environ.get("TEMPLATE_WRAPPER", "archives.html")
WRAPPER_CONFIG = {
    "archives.html": {
        "contact_url": "https://albany.libwizard.com/f/contactus?i_have_a_questi=Special%20Collections%20%26%20Archives"
    },
    "scholars_archive.html": {
        "contact_url": "https://albany.libwizard.com/f/contactus?i_have_a_questi=Scholars%20Archive%20and%20Scholarly%20Communications"
    },
}

for handler in app.logger.handlers:
    app.logger.removeHandler(handler)

handler = logging.StreamHandler()
handler.setLevel(LOG_LEVEL)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
app.logger.addHandler(handler)
app.logger.setLevel(LOG_LEVEL)


def render_challenge_template(template_name, **context):
    context["wrapper_template"] = TEMPLATE_WRAPPER
    context["contact_url"] = os.environ.get("CONTACT_URL") or WRAPPER_CONFIG.get(
        TEMPLATE_WRAPPER, {}
    ).get("contact_url", "https://albany.libwizard.com/f/contactus")
    return render_template(template_name, **context)


def verified_session():
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    return validate_cookie(
        SESSION_SIGNING_KEY, request.host.split(":", 1)[0].lower(),
        cookie, VERIFICATION_LIFETIME,
    )


def redirect_target():
    next_url = request.args.get("next", "/")
    try:
        scheme, netloc, path, query, fragment = urlsplit(next_url)
        extra_params = [
            (key, value)
            for key in request.args
            if key != "next"
            for value in request.args.getlist(key)
        ]
        if extra_params:
            params = parse_qsl(query, keep_blank_values=True) + extra_params
            next_url = urlunsplit((scheme, netloc, path, urlencode(params), fragment))
        parsed = urlparse(next_url)
    except ValueError:
        app.logger.warning("Invalid redirect blocked")
        return "/"
    if (
        any(ord(char) < 32 or ord(char) == 127 for char in next_url)
        or "\\" in next_url
        or (parsed.scheme and parsed.scheme not in ("http", "https"))
        or (parsed.netloc and parsed.netloc.lower() != request.host.lower())
        or (not parsed.netloc and not next_url.startswith("/"))
        or next_url.startswith("//")
    ):
        app.logger.warning("Unsafe redirect blocked")
        return "/"
    if parsed.path == "/challenge" or parsed.path.startswith("/challenge/"):
        return "/"
    return next_url


@app.before_request
def require_verification():
    if request.path == "/challenge" or request.path.startswith("/challenge/"):
        return
    if verified_session():
        return
    return redirect(f"/challenge?next={quote(request.url, safe='')}")


@app.route("/challenge/auth", methods=["GET", "HEAD"])
def auth():
    session_id = verified_session()
    if session_id:
        response = make_response("", 200)
        response.headers["X-Gatekeeper-Session"] = session_id
        return response
    original_uri = request.headers.get("X-Original-URI", "/")
    response = make_response("", 401)
    response.headers["X-Gatekeeper-Redirect"] = (
        f"/challenge?next={quote(original_uri, safe='')}"
    )
    return response


@app.after_request
def prevent_challenge_caching(response):
    if request.path == "/challenge" or request.path.startswith("/challenge/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/challenge", methods=["GET", "POST"])
def challenge():
    next_url = redirect_target()

    if request.method == "POST":
        token = request.form.get("cf-turnstile-response")
        if not token:
            app.logger.warning("Turnstile token missing")
            return render_challenge_template("failed.html", next_url=quote(next_url, safe="")), 403

        data = {"secret": TURNSTILE_SECRET, "response": token}
        if TRUST_PROXY_IP:
            data["remoteip"] = request.remote_addr
        try:
            resp = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=data,
                timeout=10,
            )
            resp.raise_for_status()
            result = resp.json()
        except (requests.RequestException, ValueError):
            app.logger.error("Turnstile verification service unavailable")
            return "Verification service unavailable", 503

        if not isinstance(result, dict):
            app.logger.error("Invalid response from Turnstile verification service")
            return "Verification service unavailable", 503

        hostname = result.get("hostname")
        request_hostname = request.host.split(":", 1)[0].lower()
        if (
            result.get("success") is True
            and isinstance(hostname, str)
            and hostname.lower() == request_hostname
            and hostname.lower() in ALLOWED_HOSTNAMES
        ):
            app.logger.info("Turnstile verification succeeded for %s", hostname.lower())
            response = make_response(redirect(next_url))
            response.set_cookie(
                COOKIE_NAME,
                issue_cookie(SESSION_SIGNING_KEY, request_hostname, VERIFICATION_LIFETIME),
                max_age=VERIFICATION_LIFETIME,
                secure=True,
                httponly=True,
                samesite="Lax",
                path="/",
            )
            response.delete_cookie(COOKIE_NAME, domain=".albany.edu", path="/")
            return response

        app.logger.warning("Turnstile verification failed or hostname did not match")
        return render_challenge_template("failed.html", next_url=quote(next_url, safe="")), 403

    return render_challenge_template(
        "challenge.html", sitekey=TURNSTILE_SITEKEY, next_url=quote(next_url, safe="")
    )


if __name__ == "__main__":
    app.run()
