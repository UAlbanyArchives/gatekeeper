from flask import Flask, request, make_response, redirect, render_template
import logging
import requests
import os

app = Flask(__name__)

TURNSTILE_SECRET = os.environ["TURNSTILE_SECRET"]
TURNSTILE_SITEKEY = os.environ["TURNSTILE_SITEKEY"]

# Clear any default handlers
for handler in app.logger.handlers:
    app.logger.removeHandler(handler)

# Set up a new handler that writes to stdout
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# Set global log level
app.logger.setLevel(logging.DEBUG)

# This is used internally by Nginx as auth_request
@app.route("/auth", methods=["GET", "HEAD"])
def auth():
    if request.cookies.get("turnstile_verified") == "1":
        return "", 200
    return "", 401

# This is shown to users when auth fails
@app.route("/challenge", methods=["GET", "POST"])
def challenge():
    next_url = request.args.get("next", "/")
    app.logger.debug(f"Challenge requested. Method: {request.method}, next_url: {next_url}")

    if request.method == "POST":
        token = request.form.get("cf-turnstile-response")
        app.logger.debug(f"Received POST with Turnstile token: {token}")

        if not token:
            app.logger.warning("Turnstile token missing from POST.")
            return "Verification failed", 403

        # Validate token with Cloudflare
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
            return "Verification failed", 500

        if result.get("success"):
            app.logger.info(f"Verification succeeded. Redirecting to: {next_url}")
            response = make_response(redirect(next_url))
            response.set_cookie("turnstile_verified", "1", max_age=3600)
            return response
        else:
            app.logger.warning(f"Verification failed: {result}")
            return "Verification failed", 403

    return render_template("challenge.html", sitekey=TURNSTILE_SITEKEY, next_url=next_url)

if __name__ == "__main__":
    app.run()

