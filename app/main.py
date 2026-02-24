from flask import Flask, request, abort, make_response, redirect, render_template, url_for, send_from_directory
from urllib.parse import unquote, urlencode, quote, urlparse, parse_qsl, urlsplit, urlunsplit
import logging
import requests
import os

app = Flask(
    __name__,
    static_url_path="/challenge/static",
    static_folder="static"
)

TURNSTILE_SECRET = os.environ["TURNSTILE_SECRET"]
TURNSTILE_SITEKEY = os.environ["TURNSTILE_SITEKEY"]

# Get desired log level from environment (default: WARNING)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()

# Get template wrapper configuration (default: 'archives.html')
# This allows different apps to use different wrapper templates with their own styling and navigation
TEMPLATE_WRAPPER = os.environ.get("TEMPLATE_WRAPPER", "archives.html")

# Contact URLs for each wrapper
WRAPPER_CONFIG = {
    "archives.html": {
        "contact_url": "https://albany.libwizard.com/f/contactus?i_have_a_questi=Special%20Collections%20%26%20Archives"
    },
    "scholars_archive.html": {
        "contact_url": "https://albany.libwizard.com/f/contactus?i_have_a_questi=Scholars%20Archive%20and%20Scholarly%20Communications"
    }
}

def get_wrapper_config(key, default=None):
    """Get configuration for current wrapper template"""
    return WRAPPER_CONFIG.get(TEMPLATE_WRAPPER, {}).get(key, default)

# Configure logging
for handler in app.logger.handlers:
    app.logger.removeHandler(handler)

handler = logging.StreamHandler()
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)

app.logger.addHandler(handler)
app.logger.setLevel(LOG_LEVEL)

def render_challenge_template(template_name, **context):
    """
    Custom render function that injects the wrapper template and config into context.
    This allows content templates to extend a configurable wrapper template.
    """
    context['wrapper_template'] = TEMPLATE_WRAPPER
    context['contact_url'] = os.environ.get("CONTACT_URL") or get_wrapper_config("contact_url", "https://albany.libwizard.com/f/contactus")
    return render_template(template_name, **context)

@app.before_request
def skip_challenge_for_static_and_assets():
    if request.path.startswith("/challenge/static/") or \
       request.path.endswith((".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return

    if request.path.startswith("/challenge"):
        return

    if request.cookies.get("turnstile_verified") == "1":
        return

    try:
        failures = int(request.cookies.get("turnstile_failures", 0))
    except (TypeError, ValueError):
        failures = 0

    if failures >= 3:
        app.logger.warning("User exceeded max Turnstile attempts")
        return render_challenge_template("failed.html", reason="Too many failed verification attempts."), 403

    next_url = request.url
    app.logger.debug(f"next_url from request.url: {next_url}")

    encoded_next = quote(next_url, safe='')
    app.logger.debug(f"Encoded next_url: {encoded_next}")

    return redirect(f"/challenge?next={encoded_next}")


# Routes
@app.route("/challenge/auth", methods=["GET", "HEAD"])
def auth():
    cookie = request.cookies.get("turnstile_verified")
    app.logger.debug(f"turnstile_verified cookie: {cookie}")
    if cookie == "1":
        return "", 200
    return "", 401

@app.route("/challenge", methods=["GET", "POST"])
def challenge():
    app.logger.debug(f"Request cookies: {request.cookies}")
    
    """
    # Get all query params as a dict with lists (for repeated keys)
    query_params = request.args.to_dict(flat=False)

    # Extract 'next' value (should be a list), or default
    next_parts = query_params.pop('next', ["/"])
    next_url = next_parts[0]  # first 'next' value

    # Rebuild the query string for the rest of the parameters (which belong to `next`)
    if query_params:
        # urlencode with doseq=True handles multiple values per key correctly
        qs = urlencode(query_params, doseq=True)
        next_url = f"{next_url}?{qs}"

    # Now unquote to handle any encoded characters in next_url
    next_url = unquote(next_url)
    """
    raw_next = request.args.get('next', '/')
    next_url = unquote(raw_next)

    # Parse the URL
    scheme, netloc, path, query, fragment = urlsplit(next_url)
    existing_params = dict(parse_qsl(query))

    # Get extra params passed outside of 'next'
    extra_params = {
        k: v for k, v in request.args.items() if k != 'next' and k not in existing_params
    }

    # Only merge if needed
    if extra_params:
        merged_params = {**existing_params, **extra_params}
        new_query = urlencode(merged_params, doseq=True)
        next_url = urlunsplit((scheme, netloc, path, new_query, fragment))

    # Block unsafe redirects
    parsed = urlparse(next_url)
    if parsed.netloc and parsed.netloc != request.host:
        app.logger.warning(f"Unsafe redirect blocked: {next_url}")
        next_url = "/"

    # Prevent redirect loops
    if next_url.startswith("/challenge"):
        return render_challenge_template("failed.html", reason="Invalid redirect target."), 403

    app.logger.debug(f"Challenge requested. Method: {request.method}, reconstructed next_url: {next_url}")

    if request.method == "POST":
        token = request.form.get("cf-turnstile-response")
        app.logger.debug(f"Received POST with Turnstile token: {token}")

        if not token:
            app.logger.warning("Turnstile token missing from POST.")
            return render_challenge_template("failed.html", next_url=next_url), 403

        try:
            resp = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": TURNSTILE_SECRET,
                    "response": token,
                    "remoteip": request.remote_addr
                }
            )
            result = resp.json()
            app.logger.debug(f"Cloudflare response: {result}")
        except Exception as e:
            app.logger.error(f"Error contacting Cloudflare: {e}")
            return "500 Verification failed", 500

        if result.get("success"):
            app.logger.debug(f"Verification succeeded. Redirecting to: {next_url}")
            if not next_url or next_url.startswith("/challenge"):
                next_url = "/"
            response = make_response(redirect(next_url))
            response.set_cookie(
                "turnstile_verified",
                "1",
                max_age=8 * 3600,  # Set for 8 hours as 3600 is an hour
                secure=True,
                httponly=True,
                samesite="None",
                domain=".albany.edu",
                path="/"
            )
            # Clear failure count
            response.set_cookie("turnstile_failures", "", max_age=0, path="/")
            return response
        else:
            app.logger.warning(f"Full response: {result}, IP: {request.remote_addr}")
            try:
                failures = int(request.cookies.get("turnstile_failures", 0))
            except (TypeError, ValueError):
                failures = 0
            app.logger.warning(f"Verification failed attempt #{failures}")

            response = make_response(render_challenge_template("failed.html", next_url=next_url), 403)
            response.set_cookie(
                "turnstile_failures",
                str(failures),
                max_age=600,  # 10 minutes
                path="/",
                samesite="Lax"
            )
            return response
    else:
        app.logger.debug(f"Received {request.method} request.")

    encoded_next = quote(next_url, safe='/?:=&')
    return render_challenge_template("challenge.html", sitekey=TURNSTILE_SITEKEY, next_url=encoded_next)

if __name__ == "__main__":
    app.run()
