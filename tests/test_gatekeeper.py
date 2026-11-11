import os
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from werkzeug.middleware.proxy_fix import ProxyFix

os.environ.update(
    TURNSTILE_SECRET="test-secret",
    TURNSTILE_SITEKEY="test-sitekey",
    SESSION_SIGNING_KEY="a1" * 32,
    TURNSTILE_ALLOWED_HOSTNAMES="archives.albany.edu,scholars.albany.edu",
    TRUST_PROXY_IP="false",
)

from app import main
from gatekeeper_cookie import issue_cookie, parse_key, parse_lifetime, validate_cookie


class GatekeeperTests(unittest.TestCase):
    def setUp(self):
        self.client = main.app.test_client()
        self.base_url = "https://archives.albany.edu"

    def auth(self):
        return self.client.get("/challenge/auth", base_url=self.base_url)

    def verify(self, result, url="/challenge?next=/protected"):
        response = Mock()
        response.json.return_value = result
        with patch.object(main.requests, "post", return_value=response) as post:
            result = self.client.post(
                url, data={"cf-turnstile-response": "test-token"}, base_url=self.base_url
            )
        return result, post

    def test_missing_and_forged_cookies_are_rejected(self):
        self.assertEqual(self.auth().status_code, 401)
        for value in (
            "1", "verified",
            issue_cookie(main.SESSION_SIGNING_KEY, "archives.albany.edu", 1800) + "x",
        ):
            self.client.set_cookie(
                "turnstile_verified", value, domain="albany.edu", origin_only=False
            )
            self.assertEqual(self.auth().status_code, 401)
            self.assertEqual(
                self.client.get("/protected", base_url=self.base_url).status_code, 302
            )

    def test_success_issues_host_only_signed_cookie_and_authenticates(self):
        response, post = self.verify({"success": True, "hostname": "archives.albany.edu"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/protected")
        cookie = response.headers["Set-Cookie"]
        for attribute in ("Max-Age=1800", "Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(attribute, cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertIn("Domain=albany.edu", response.headers.getlist("Set-Cookie")[1])
        auth = self.auth()
        self.assertEqual(auth.status_code, 200)
        session_id = auth.headers["X-Gatekeeper-Session"]
        self.assertEqual(len(session_id), 32)
        self.assertNotIn(session_id, response.location)
        shared_auth = self.client.get("/challenge/auth", base_url="https://scholars.albany.edu")
        self.assertEqual(shared_auth.status_code, 401)
        self.assertEqual(self.client.get("/protected", base_url=self.base_url).status_code, 404)
        self.assertNotIn("remoteip", post.call_args.kwargs["data"])
        self.assertEqual(post.call_args.kwargs["timeout"], 10)

    def test_expired_cookie_is_rejected_server_side(self):
        token = issue_cookie(main.SESSION_SIGNING_KEY, "archives.albany.edu", 1800, now=100000)
        self.client.set_cookie(
            "turnstile_verified", token, domain="albany.edu", origin_only=False
        )
        with patch("gatekeeper_cookie.time.time", return_value=100000 + 1799):
            self.assertEqual(self.auth().status_code, 200)
        with patch("gatekeeper_cookie.time.time", return_value=100000 + 1800):
            self.assertEqual(self.auth().status_code, 401)

    def test_signature_binds_host_and_lifetime(self):
        key = main.SESSION_SIGNING_KEY
        token = issue_cookie(key, "archives.albany.edu", 1800, now=100)
        self.assertIsNotNone(validate_cookie(key, "archives.albany.edu", token, 1800, now=101))
        self.assertIsNone(validate_cookie(key, "scholars.albany.edu", token, 1800, now=101))
        self.assertIsNone(validate_cookie(b"different-key", "archives.albany.edu", token, 1800, now=101))
        self.assertIsNone(validate_cookie(key, "archives.albany.edu", token, 1799, now=101))
        self.assertIsNone(validate_cookie(key, "archives.albany.edu", token, 1800, now=99))
        self.assertIsNone(validate_cookie(key, "archives.albany.edu", token.replace(".1900.", ".1901."), 1801, now=101))

    def test_key_and_lifetime_configuration_validation(self):
        for value in ("a" * 63, "zz" * 32, "abc"):
            with self.subTest(key=value), self.assertRaises(ValueError):
                parse_key(value)
        for value in ("0", "-1", "86401", "oops"):
            with self.subTest(lifetime=value), self.assertRaises(ValueError):
                parse_lifetime(value)
        self.assertEqual(parse_lifetime("1800"), 1800)

    def test_each_verification_gets_a_distinct_session(self):
        self.verify({"success": True, "hostname": "archives.albany.edu"})
        first = self.auth().headers["X-Gatekeeper-Session"]
        self.verify({"success": True, "hostname": "archives.albany.edu"})
        second = self.auth().headers["X-Gatekeeper-Session"]
        self.assertNotEqual(first, second)

    def test_invalid_or_mismatched_results_do_not_issue_cookie(self):
        for result in (
            {"success": False, "hostname": "archives.albany.edu"},
            {"success": "true", "hostname": "archives.albany.edu"},
            {"success": True},
            {"success": True, "hostname": "scholars.albany.edu"},
            {"success": True, "hostname": "other.albany.edu"},
        ):
            with self.subTest(result=result):
                response, _ = self.verify(result)
                self.assertEqual(response.status_code, 403)
                self.assertNotIn("Set-Cookie", response.headers)

    def test_hostname_must_be_allowlisted_even_if_it_matches_request(self):
        response = Mock()
        response.json.return_value = {"success": True, "hostname": "other.albany.edu"}
        with patch.object(main.requests, "post", return_value=response):
            result = self.client.post(
                "/challenge", data={"cf-turnstile-response": "test-token"},
                base_url="https://other.albany.edu",
            )
        self.assertEqual(result.status_code, 403)
        self.assertNotIn("Set-Cookie", result.headers)

    def test_missing_token_and_verification_outage_fail_closed(self):
        result = self.client.post("/challenge", base_url=self.base_url)
        self.assertEqual(result.status_code, 403)
        with patch.object(main.requests, "post", side_effect=requests.Timeout):
            result = self.client.post(
                "/challenge", data={"cf-turnstile-response": "test-token"}, base_url=self.base_url
            )
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("Set-Cookie", result.headers)
        result, _ = self.verify(["unexpected"])
        self.assertEqual(result.status_code, 503)

    def test_assets_and_challenge_are_public_but_suffixes_do_not_bypass_gate(self):
        self.assertEqual(self.client.get("/challenge", base_url=self.base_url).status_code, 200)
        response = self.client.get("/challenge/static/main.css", base_url=self.base_url)
        self.assertEqual(response.status_code, 200)
        response.close()
        self.assertEqual(self.client.get("/private.css", base_url=self.base_url).status_code, 302)

    def test_auth_redirect_encodes_original_uri_without_losing_query(self):
        original = "/search%2Fpage?next=one&tag=a&tag=b%26c"
        response = self.client.get(
            "/challenge/auth", base_url=self.base_url, headers={"X-Original-URI": original}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        challenge = response.headers["X-Gatekeeper-Redirect"]
        self.assertEqual(parse_qs(urlsplit(challenge).query)["next"], [original])
        response, _ = self.verify({"success": True, "hostname": "archives.albany.edu"}, challenge)
        self.assertEqual(response.location, original)

    def test_ip_is_only_sent_when_trusted_proxy_mode_is_enabled(self):
        response = Mock()
        response.json.return_value = {"success": True, "hostname": "archives.albany.edu"}
        proxy = ProxyFix(main.app.wsgi_app, x_for=1)
        with patch.object(main, "TRUST_PROXY_IP", True), \
             patch.object(main.app, "wsgi_app", proxy), \
             patch.object(main.requests, "post", return_value=response) as post:
            result = self.client.post(
                "/challenge", data={"cf-turnstile-response": "test-token"},
                base_url=self.base_url, environ_overrides={"REMOTE_ADDR": "192.0.2.1"},
                headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
            )
        self.assertEqual(result.status_code, 302)
        self.assertEqual(post.call_args.kwargs["data"]["remoteip"], "198.51.100.1")

    def test_redirect_is_safe_and_preserves_query_parameters(self):
        response, _ = self.verify(
            {"success": True, "hostname": "archives.albany.edu"},
            "/challenge?next=/search%3Fq%3Done&q=two&empty=",
        )
        self.assertEqual(parse_qs(urlsplit(response.location).query, keep_blank_values=True), {
            "q": ["one", "two"], "empty": [""]
        })
        for target in ("https%3A%2F%2Fevil.example", "%2F%2Fevil.example", "javascript%3Aalert(1)"):
            with self.subTest(target=target):
                response, _ = self.verify(
                    {"success": True, "hostname": "archives.albany.edu"},
                    "/challenge?next=" + target,
                )
                self.assertEqual(response.location, "/")


if __name__ == "__main__":
    unittest.main()
