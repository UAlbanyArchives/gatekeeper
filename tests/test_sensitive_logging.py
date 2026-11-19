import logging
from http.cookies import SimpleCookie
from unittest.mock import Mock, patch

from app import main


def test_success_does_not_log_key_signed_cookie_or_turnstile_token(caplog):
    turnstile_token = "turnstile-response-secret-for-test"
    cloudflare_response_token = "cloudflare-response-token-for-test"
    siteverify_response = Mock()
    siteverify_response.json.return_value = {
        "success": True,
        "response": cloudflare_response_token,
    }

    with caplog.at_level(logging.DEBUG, logger=main.app.logger.name):
        with patch.object(
            main.requests, "post", return_value=siteverify_response
        ):
            response = main.app.test_client().post(
                "/challenge",
                data={"cf-turnstile-response": turnstile_token},
                base_url="https://archives.albany.edu",
            )

    cookies = SimpleCookie()
    for header in response.headers.getlist("Set-Cookie"):
        cookies.load(header)
    signed_cookie = cookies["gatekeeper_verified"].value

    assert response.status_code == 302
    assert main.GATEKEEPER_KEY.hex() not in caplog.text
    assert signed_cookie not in caplog.text
    assert turnstile_token not in caplog.text
    assert cloudflare_response_token not in caplog.text
