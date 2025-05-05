from flask import Flask, request, make_response, redirect, render_template
import requests
import os

app = Flask(__name__)

TURNSTILE_SECRET = os.environ["TURNSTILE_SECRET"]
TURNSTILE_SITEKEY = os.environ["TURNSTILE_SITEKEY"]

# This is used internally by Nginx as auth_request
@app.route("/auth", methods=["GET", "HEAD"])
def auth():
    if request.cookies.get("turnstile_verified") == "1":
        return "", 200
    return "", 401

# This is shown to users when auth fails
@app.route("/challenge", methods=["GET", "POST"])
def challenge():
    if request.method == "POST" and "cf-turnstile-response" in request.form:
        # Validate with Cloudflare
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET,
                "response": request.form["cf-turnstile-response"],
                "remoteip": request.remote_addr
            }
        )
        if resp.json().get("success"):
            next_url = request.form.get("next", "/")
            response = make_response(redirect(next_url))
            response.set_cookie("turnstile_verified", "1", max_age=3600)
            return response
        return "Verification failed", 403

    next_url = request.args.get("next", "/")
    return render_template("challenge.html", sitekey=TURNSTILE_SITEKEY, next_url=next_url)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

