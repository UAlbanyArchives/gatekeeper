import hashlib
import hmac
from unittest.mock import patch

import pytest

from app.gatekeeper_cookie import (
    create_gatekeeper_cookie,
    create_observe_cookie,
    load_gatekeeper_config,
    load_signing_key,
    verify_gatekeeper_cookie,
)


KEY_HEX = "0123456789abcdef" * 4
KEY = bytes.fromhex(KEY_HEX)


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_load_signing_key_strips_trailing_line_endings(tmp_path, line_ending):
    key_file = tmp_path / "signing-key"
    key_file.write_bytes((KEY_HEX + line_ending).encode("ascii"))

    assert load_signing_key(str(key_file)) == KEY


@pytest.mark.parametrize(
    "contents",
    [
        "g" + KEY_HEX[1:],
        KEY_HEX[:-1],
        KEY_HEX + "0",
        "",
    ],
)
def test_load_signing_key_rejects_non_hex_or_wrong_length(tmp_path, contents):
    key_file = tmp_path / "signing-key"
    key_file.write_text(contents, encoding="ascii")

    with pytest.raises(ValueError, match="64 hexadecimal characters"):
        load_signing_key(str(key_file))


def test_load_signing_key_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="readable regular file"):
        load_signing_key(str(tmp_path / "missing-key"))


def test_load_signing_key_rejects_missing_path():
    with pytest.raises(ValueError, match="GATEKEEPER_KEY_FILE"):
        load_signing_key(None)


def test_load_signing_key_rejects_directory(tmp_path):
    with pytest.raises(ValueError, match="readable regular file"):
        load_signing_key(str(tmp_path))


def test_load_signing_key_rejects_unreadable_file(tmp_path):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")
    with patch("builtins.open", side_effect=PermissionError):
        with pytest.raises(ValueError, match="readable regular file"):
            load_signing_key(str(key_file))


def test_load_signing_key_error_does_not_expose_key(tmp_path):
    secret_like_value = "z" * 64
    key_file = tmp_path / "signing-key"
    key_file.write_text(secret_like_value, encoding="ascii")

    with pytest.raises(ValueError) as error:
        load_signing_key(str(key_file))

    assert secret_like_value not in str(error.value)


def test_load_gatekeeper_config_normalizes_hostname_and_reads_values(tmp_path):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")

    key, hostname, ttl = load_gatekeeper_config(
        {
            "GATEKEEPER_KEY_FILE": str(key_file),
            "GATEKEEPER_HOSTNAME": "  Archives.Albany.EDU ",
            "GATEKEEPER_COOKIE_TTL": "1800",
        }
    )

    assert key == KEY
    assert hostname == "archives.albany.edu"
    assert ttl == 1800


@pytest.mark.parametrize(
    "environment, missing_setting",
    [
        ({}, "GATEKEEPER_KEY_FILE"),
        (
            {"GATEKEEPER_KEY_FILE": "path"},
            "GATEKEEPER_HOSTNAME",
        ),
        (
            {
                "GATEKEEPER_KEY_FILE": "path",
                "GATEKEEPER_HOSTNAME": "archives.albany.edu",
            },
            "GATEKEEPER_COOKIE_TTL",
        ),
    ],
)
def test_load_gatekeeper_config_rejects_missing_settings(environment, missing_setting):
    with pytest.raises(ValueError, match=missing_setting):
        load_gatekeeper_config(environment)


def test_load_gatekeeper_config_rejects_non_ascii_hostname(tmp_path):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")

    with pytest.raises(ValueError, match="must be ASCII"):
        load_gatekeeper_config(
            {
                "GATEKEEPER_KEY_FILE": str(key_file),
                "GATEKEEPER_HOSTNAME": "archives.albany.édu",
                "GATEKEEPER_COOKIE_TTL": "1800",
            }
        )


@pytest.mark.parametrize("ttl", ["invalid", "1.5", ""])
def test_load_gatekeeper_config_rejects_non_integer_ttl(tmp_path, ttl):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")
    environment = {
        "GATEKEEPER_KEY_FILE": str(key_file),
        "GATEKEEPER_HOSTNAME": "archives.albany.edu",
        "GATEKEEPER_COOKIE_TTL": ttl,
    }

    with pytest.raises(ValueError, match="must be an integer"):
        load_gatekeeper_config(environment)


@pytest.mark.parametrize("ttl", ["0", "-1", "86401"])
def test_load_gatekeeper_config_rejects_ttl_out_of_range(tmp_path, ttl):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")
    environment = {
        "GATEKEEPER_KEY_FILE": str(key_file),
        "GATEKEEPER_HOSTNAME": "archives.albany.edu",
        "GATEKEEPER_COOKIE_TTL": ttl,
    }

    with pytest.raises(ValueError, match="between 1 and 86400"):
        load_gatekeeper_config(environment)


@pytest.mark.parametrize("ttl", ["1", "86400"])
def test_load_gatekeeper_config_accepts_ttl_boundaries(tmp_path, ttl):
    key_file = tmp_path / "signing-key"
    key_file.write_text(KEY_HEX, encoding="ascii")

    _, _, configured_ttl = load_gatekeeper_config(
        {
            "GATEKEEPER_KEY_FILE": str(key_file),
            "GATEKEEPER_HOSTNAME": "archives.albany.edu",
            "GATEKEEPER_COOKIE_TTL": ttl,
        }
    )

    assert configured_ttl == int(ttl)


def test_cookie_matches_independently_calculated_hmac():
    cookie = create_gatekeeper_cookie(
        "Archives.Albany.edu", 1800, KEY, now=1795113000
    )
    expiry = 1795113000 + 1800
    message = "archives.albany.edu|v1|{}".format(expiry).encode("ascii")
    expected_signature = hmac.new(KEY, message, hashlib.sha256).hexdigest()

    assert cookie == "v1.{}.{}".format(expiry, expected_signature)


def test_observe_cookie_matches_independently_calculated_hmac():
    nonce = "0123456789abcdef" * 2
    with patch("app.gatekeeper_cookie.secrets.token_hex", return_value=nonce) as token_hex:
        cookie = create_observe_cookie("Archives.Albany.EDU", 1800, KEY, now=1795113000)

    expiry = 1795113000 + 1800
    message = "archives.albany.edu|v2|{}|{}".format(expiry, nonce).encode("ascii")
    expected_signature = hmac.new(KEY, message, hashlib.sha256).hexdigest()

    token_hex.assert_called_once_with(16)
    assert cookie == "v2.{}.{}.{}".format(expiry, nonce, expected_signature)


def test_cookie_signing_is_deterministic_for_identical_inputs():
    first = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)
    second = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)

    assert first == second


def test_changing_expiry_changes_signature():
    first = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)
    second = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1001)

    assert first.split(".")[2] != second.split(".")[2]


def test_changing_hostname_changes_signature():
    archive_cookie = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)
    scholars_cookie = create_gatekeeper_cookie("scholars.albany.edu", 1800, KEY, now=1000)

    assert archive_cookie.split(".")[1] == scholars_cookie.split(".")[1]
    assert archive_cookie.split(".")[2] != scholars_cookie.split(".")[2]


def test_cookie_signer_normalizes_hostname_to_lowercase():
    mixed_case = create_gatekeeper_cookie("Archives.Albany.EDU", 1800, KEY, now=1000)
    lowercase = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)

    assert mixed_case == lowercase


def test_cookie_verifier_accepts_a_valid_signed_cookie():
    cookie = create_gatekeeper_cookie("Archives.Albany.EDU", 1800, KEY, now=1000)

    assert verify_gatekeeper_cookie(
        cookie, "archives.albany.edu", 1800, KEY, now=1000
    )


@pytest.mark.parametrize(
    "cookie",
    [
        "",
        "1",
        "v1.invalid.signature",
        "v1.2800." + "0" * 64,
    ],
)
def test_cookie_verifier_rejects_malformed_or_invalid_cookies(cookie):
    assert not verify_gatekeeper_cookie(
        cookie, "archives.albany.edu", 1800, KEY, now=1000
    )


def test_cookie_verifier_rejects_expired_cookie():
    cookie = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)

    assert not verify_gatekeeper_cookie(
        cookie, "archives.albany.edu", 1800, KEY, now=2800
    )


def test_cookie_verifier_rejects_cookie_for_another_hostname():
    cookie = create_gatekeeper_cookie("archives.albany.edu", 1800, KEY, now=1000)

    assert not verify_gatekeeper_cookie(
        cookie, "scholars.albany.edu", 1800, KEY, now=1000
    )
