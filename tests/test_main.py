import hashlib
import hmac
import os
import unittest
from http.cookies import SimpleCookie
import time
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch


os.environ["TURNSTILE_SECRET"] = "test-turnstile-secret"
os.environ["TURNSTILE_SITEKEY"] = "test-turnstile-sitekey"

from app import main


class GatekeeperTestCase(unittest.TestCase):
    def setUp(self):
        main.app.config.update(TESTING=True)
        self.client = main.app.test_client()
        self.base_url = "https://archives.albany.edu"

    def post_challenge(self, result=None, next_url="/records?q=example", token="test-token"):
        siteverify_response = Mock()
        siteverify_response.json.return_value = (
            {"success": True} if result is None else result
        )
        with patch.object(main.requests, "post", return_value=siteverify_response) as post:
            response = self.client.post(
                "/challenge",
                query_string={"next": next_url},
                data={"cf-turnstile-response": token} if token is not None else {},
                base_url=self.base_url,
            )
        return response, post

    def response_cookies(self, response):
        cookies = SimpleCookie()
        for header in response.headers.getlist("Set-Cookie"):
            cookies.load(header)
        return cookies

    def set_cookie(self, name, value):
        self.client.set_cookie(name, value, domain="archives.albany.edu")

    def set_signed_cookie(self, now=None):
        value = main.create_gatekeeper_cookie(
            main.GATEKEEPER_HOSTNAME,
            main.GATEKEEPER_COOKIE_TTL,
            main.GATEKEEPER_KEY,
            now=int(time.time()) if now is None else now,
        )
        self.set_cookie("gatekeeper_verified", value)


class RequestGateTests(GatekeeperTestCase):
    def test_unverified_request_redirects_to_challenge_with_full_url(self):
        response = self.client.get(
            "/records?q=one&tag=two", base_url=self.base_url, follow_redirects=False
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            parse_qs(urlsplit(response.headers["Location"]).query)["next"],
            ["https://archives.albany.edu/records?q=one&tag=two"],
        )

    def test_signed_cookie_allows_protected_request(self):
        self.set_signed_cookie()

        response = self.client.get("/records", base_url=self.base_url)

        self.assertEqual(response.status_code, 404)

    def test_legacy_cookie_does_not_authorize_protected_request(self):
        self.set_cookie("turnstile_verified", "1")

        response = self.client.get("/records", base_url=self.base_url)

        self.assertEqual(response.status_code, 302)

    def test_observe_cookie_does_not_authorize_protected_request(self):
        self.set_cookie(
            "gatekeeper_observe",
            main.create_observe_cookie(
                main.GATEKEEPER_HOSTNAME, main.GATEKEEPER_COOKIE_TTL, main.GATEKEEPER_KEY
            ),
        )

        response = self.client.get("/records", base_url=self.base_url)

        self.assertEqual(response.status_code, 302)

    def test_invalid_signed_cookie_values_do_not_authorize_request(self):
        for value in ("true", "0", "1anything", ""):
            with self.subTest(value=value):
                client = main.app.test_client()
                client.set_cookie(
                    "gatekeeper_verified", value, domain="archives.albany.edu"
                )

                response = client.get("/records", base_url=self.base_url)

                self.assertEqual(response.status_code, 302)

    def test_static_suffix_is_exempt_from_challenge(self):
        response = self.client.get("/missing.css", base_url=self.base_url)

        self.assertEqual(response.status_code, 404)
        self.assertIsNone(response.location)

    def test_challenge_prefix_is_exempt_from_challenge(self):
        response = self.client.get("/challenge/not-a-route", base_url=self.base_url)

        self.assertEqual(response.status_code, 404)
        self.assertIsNone(response.location)

    def test_repeated_failed_attempts_reach_failure_page(self):
        self.set_cookie("turnstile_failures", "3")

        response = self.client.get("/records", base_url=self.base_url)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Too many failed verification attempts.", response.data)

    def test_invalid_failure_cookie_is_treated_as_zero(self):
        self.set_cookie("turnstile_failures", "not-a-number")

        response = self.client.get("/records", base_url=self.base_url)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.startswith("/challenge?"))

    def test_static_and_challenge_exemptions_precede_failure_limit(self):
        self.set_cookie("turnstile_failures", "3")

        asset = self.client.get("/missing.js", base_url=self.base_url)
        challenge = self.client.get("/challenge", base_url=self.base_url)

        self.assertEqual(asset.status_code, 404)
        self.assertIsNone(asset.location)
        self.assertEqual(challenge.status_code, 200)


class AuthEndpointTests(GatekeeperTestCase):
    def test_observe_cookie_does_not_authorize_auth_endpoint(self):
        self.set_cookie(
            "gatekeeper_observe",
            main.create_observe_cookie(
                main.GATEKEEPER_HOSTNAME, main.GATEKEEPER_COOKIE_TTL, main.GATEKEEPER_KEY
            ),
        )

        self.assertEqual(
            self.client.get("/challenge/auth", base_url=self.base_url).status_code, 401
        )

    def test_auth_endpoint_rejects_missing_or_invalid_signed_cookie(self):
        self.assertEqual(
            self.client.get("/challenge/auth", base_url=self.base_url).status_code, 401
        )
        self.set_cookie("gatekeeper_verified", "invalid")
        self.assertEqual(
            self.client.get("/challenge/auth", base_url=self.base_url).status_code, 401
        )

    def test_auth_endpoint_accepts_signed_cookie_for_get_and_head(self):
        self.set_signed_cookie()

        self.assertEqual(
            self.client.get("/challenge/auth", base_url=self.base_url).status_code, 200
        )
        self.assertEqual(
            self.client.head("/challenge/auth", base_url=self.base_url).status_code, 200
        )


class ChallengePageTests(GatekeeperTestCase):
    def test_get_challenge_renders_site_key_and_widget(self):
        response = self.client.get("/challenge", base_url=self.base_url)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"test-turnstile-sitekey", response.data)
        self.assertIn(b"cf-turnstile-response", response.data)
        self.assertIn(b"challenges.cloudflare.com/turnstile", response.data)

    def test_get_challenge_preserves_next_url_in_form(self):
        response = self.client.get(
            "/challenge?next=%2Frecords%3Fq%3Done", base_url=self.base_url
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="next" value="/records?q=one"', response.data)

    def test_challenge_loop_target_renders_failure_page(self):
        response = self.client.get(
            "/challenge?next=%2Fchallenge%3Fnext%3D%2Frecords",
            base_url=self.base_url,
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Invalid redirect target.", response.data)

    def test_external_redirect_target_is_replaced_with_root_after_success(self):
        response, _ = self.post_challenge(
            next_url="https://attacker.example/collect"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_same_host_absolute_target_is_allowed_after_success(self):
        response, _ = self.post_challenge(
            next_url="https://archives.albany.edu/records"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://archives.albany.edu/records")

    def test_empty_next_target_redirects_to_root_after_success(self):
        response, _ = self.post_challenge(next_url="")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_extra_query_parameters_are_merged(self):
        siteverify_response = Mock()
        siteverify_response.json.return_value = {"success": True}
        with patch.object(main.requests, "post", return_value=siteverify_response):
            response = self.client.post(
                "/challenge?next=%2Frecords%3Fexisting%3Done&new=two",
                data={"cf-turnstile-response": "test-token"},
                base_url=self.base_url,
            )
        self.assertEqual(response.location, "/records?existing=one&new=two")

    def test_failure_page_uses_wrapper_contact_link(self):
        response = self.client.get("/challenge", base_url=self.base_url)

        self.assertIn(b"libwizard.com/f/contactus", response.data)

    def test_scholars_wrapper_uses_its_contact_link(self):
        with patch.object(main, "TEMPLATE_WRAPPER", "scholars_archive.html"):
            response = self.client.get("/challenge", base_url=self.base_url)

        self.assertIn(b"Scholarly Communications Services", response.data)

    def test_contact_url_environment_override_is_used(self):
        with patch.dict(os.environ, {"CONTACT_URL": "https://example.test/contact"}):
            response = self.client.get("/challenge", base_url=self.base_url)

        self.assertIn(b"https://example.test/contact", response.data)


class TurnstileSubmissionTests(GatekeeperTestCase):
    def test_missing_turnstile_token_returns_forbidden_without_siteverify_call(self):
        with patch.object(main.requests, "post") as post:
            response = self.client.post("/challenge", base_url=self.base_url)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Verification Failed", response.data)
        self.assertNotIn("gatekeeper_verified", self.response_cookies(response))
        post.assert_not_called()

    def test_successful_verification_sets_both_cookies_and_clears_failures(self):
        started = int(time.time())
        response, post = self.post_challenge()
        completed = int(time.time())

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/records?q=example")
        cookies = self.response_cookies(response)
        self.assertNotIn("turnstile_verified", cookies)
        self.assertIn("gatekeeper_verified", cookies)
        signed_value = cookies["gatekeeper_verified"].value
        version, expiry, signature = signed_value.split(".")
        self.assertEqual(version, "v1")
        self.assertEqual(
            cookies["gatekeeper_verified"]["max-age"],
            str(main.GATEKEEPER_COOKIE_TTL),
        )
        self.assertTrue(cookies["gatekeeper_verified"]["secure"])
        self.assertTrue(cookies["gatekeeper_verified"]["httponly"])
        self.assertEqual(cookies["gatekeeper_verified"]["samesite"], "Lax")
        self.assertEqual(cookies["gatekeeper_verified"]["path"], "/")
        self.assertFalse(cookies["gatekeeper_verified"]["domain"])
        self.assertGreaterEqual(
            int(expiry), started + main.GATEKEEPER_COOKIE_TTL
        )
        self.assertLessEqual(
            int(expiry), completed + main.GATEKEEPER_COOKIE_TTL
        )
        message = "{}|v1|{}".format(main.GATEKEEPER_HOSTNAME, expiry).encode("ascii")
        expected_signature = hmac.new(
            main.GATEKEEPER_KEY, message, hashlib.sha256
        ).hexdigest()
        self.assertEqual(signature, expected_signature)
        self.assertIn("gatekeeper_observe", cookies)
        observe_cookie = cookies["gatekeeper_observe"]
        observe_version, observe_expiry, nonce, observe_signature = observe_cookie.value.split(".")
        self.assertEqual(observe_version, "v2")
        self.assertRegex(nonce, r"^[0-9a-f]{32}$")
        self.assertRegex(observe_signature, r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(int(observe_expiry), started + main.GATEKEEPER_COOKIE_TTL)
        self.assertLessEqual(int(observe_expiry), completed + main.GATEKEEPER_COOKIE_TTL)
        self.assertEqual(observe_cookie["max-age"], str(main.GATEKEEPER_COOKIE_TTL))
        self.assertTrue(observe_cookie["secure"])
        self.assertTrue(observe_cookie["httponly"])
        self.assertEqual(observe_cookie["samesite"], "Lax")
        self.assertEqual(observe_cookie["path"], "/")
        self.assertFalse(observe_cookie["domain"])
        self.assertEqual(cookies["turnstile_failures"]["max-age"], "0")
        post.assert_called_once()
        self.assertEqual(
            post.call_args.args[0],
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        )
        self.assertEqual(
            post.call_args.kwargs["data"],
            {
                "secret": "test-turnstile-secret",
                "response": "test-token",
                "remoteip": "127.0.0.1",
            },
        )

    def test_successful_verifications_generate_distinct_observe_nonces(self):
        first, _ = self.post_challenge()
        second, _ = self.post_challenge()

        first_nonce = self.response_cookies(first)["gatekeeper_observe"].value.split(".")[2]
        second_nonce = self.response_cookies(second)["gatekeeper_observe"].value.split(".")[2]
        self.assertNotEqual(first_nonce, second_nonce)

    def test_failed_verification_returns_forbidden_and_sets_failure_cookie(self):
        response, post = self.post_challenge({"success": False})

        self.assertEqual(response.status_code, 403)
        cookies = self.response_cookies(response)
        self.assertEqual(cookies["turnstile_failures"].value, "0")
        self.assertEqual(cookies["turnstile_failures"]["max-age"], "600")
        self.assertEqual(cookies["turnstile_failures"]["samesite"], "Lax")
        self.assertNotIn("gatekeeper_verified", cookies)
        self.assertNotIn("gatekeeper_observe", cookies)
        post.assert_called_once()

    def test_invalid_failure_count_is_reset_when_verification_fails(self):
        self.set_cookie("turnstile_failures", "not-a-number")
        response, _ = self.post_challenge({"success": False})

        self.assertEqual(self.response_cookies(response)["turnstile_failures"].value, "0")

    def test_siteverify_network_error_returns_server_error(self):
        with patch.object(
            main.requests, "post", side_effect=main.requests.RequestException("offline")
        ):
            response = self.client.post(
                "/challenge",
                data={"cf-turnstile-response": "test-token"},
                base_url=self.base_url,
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_data(as_text=True), "500 Verification failed")

    def test_siteverify_invalid_json_returns_server_error(self):
        siteverify_response = Mock()
        siteverify_response.json.side_effect = ValueError("invalid JSON")
        with patch.object(main.requests, "post", return_value=siteverify_response):
            response = self.client.post(
                "/challenge",
                data={"cf-turnstile-response": "test-token"},
                base_url=self.base_url,
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_data(as_text=True), "500 Verification failed")


if __name__ == "__main__":
    unittest.main()
