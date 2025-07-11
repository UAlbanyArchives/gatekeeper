from flask import Flask, request, abort, make_response, redirect, render_template, url_for, send_from_directory
from urllib.parse import unquote, urlencode, quote
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

# Configure logging
for handler in app.logger.handlers:
    app.logger.removeHandler(handler)

handler = logging.StreamHandler()
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)

app.logger.addHandler(handler)
app.logger.setLevel(LOG_LEVEL)

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
        return render_template("failed.html", reason="Too many failed verification attempts."), 403

    next_url = request.full_path or request.path or "/"
    # Strip trailing '?' added by request.full_path if no query string
    if next_url.endswith('?'):
        next_url = next_url[:-1]

    # Manually encode the next_url to preserve the full query string
    encoded_next = quote(next_url, safe='')

    # Build redirect manually to avoid double-encoding
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
    
    next_url = request.args.get("next")
    if not next_url:
        return render_template("failed.html", reason="Missing redirect target."), 403
    old_next_url = next_url
    # Decode the next_url to get the full URL with query params
    next_url = unquote(next_url)

    # Prevent redirect loop:
    if next_url.startswith("/challenge"):
        return render_template("failed.html", reason="Invalid redirect target."), 403

    app.logger.debug(f"Challenge requested. Method: {request.method}, next_url: {next_url}")
    app.logger.debug(f"Challenge requested. Method: {request.method}, next_url: {old_next_url}")

    if request.method == "POST":
        token = request.form.get("cf-turnstile-response")
        app.logger.debug(f"Received POST with Turnstile token: {token}")

        if not token:
            app.logger.warning("Turnstile token missing from POST.")
            return render_template("failed.html", next_url=next_url), 403

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
                samesite="Lax",
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

            response = make_response(render_template("failed.html", next_url=next_url), 403)
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

    return render_template("challenge.html", sitekey=TURNSTILE_SITEKEY, next_url=next_url)

if __name__ == "__main__":
    app.run()
