import os
import subprocess
import sys
import time

import pytest

from app.gatekeeper_cookie import create_gatekeeper_cookie


KEY_HEX = "0123456789abcdef" * 4
KEY = bytes.fromhex(KEY_HEX)
HOSTNAME = "archives.albany.edu"
MAX_LIFETIME = 1800
VERIFIER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "apache", "gatekeeper_map.py")
)


def run_verifier(key_file, cookies, hostname=HOSTNAME, max_lifetime=MAX_LIFETIME):
    return subprocess.run(
        [
            sys.executable,
            VERIFIER,
            str(key_file),
            hostname,
            str(max_lifetime),
        ],
        input="".join(cookie + "\n" for cookie in cookies),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "signing-key"
    path.write_text(KEY_HEX + "\n", encoding="ascii")
    return path


def test_persistent_verifier_accepts_flask_issuer_cookie(key_file):
    now = int(time.time())
    cookie = create_gatekeeper_cookie(HOSTNAME, MAX_LIFETIME, KEY, now=now)

    result = run_verifier(key_file, [cookie])

    assert result.returncode == 0
    assert result.stdout == "VALID\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "cookie_factory",
    [
        lambda now, valid: "1",
        lambda now, valid: "v1",
        lambda now, valid: "v1.not-a-timestamp." + "a" * 64,
        lambda now, valid: valid[:-1] + ("0" if valid[-1] != "0" else "1"),
        lambda now, valid: "v1.{}.{}".format(
            int(valid.split(".")[1]) + 1, valid.split(".")[2]
        ),
    ],
)
def test_verifier_rejects_malformed_or_modified_cookie(key_file, cookie_factory):
    now = int(time.time())
    valid = create_gatekeeper_cookie(HOSTNAME, MAX_LIFETIME, KEY, now=now)
    cookie = cookie_factory(now, valid)

    result = run_verifier(key_file, [cookie])

    assert result.returncode == 0
    assert result.stdout == "INVALID\n"
    assert result.stderr == ""


def test_verifier_rejects_expired_cookie(key_file):
    now = int(time.time())
    expired = create_gatekeeper_cookie(
        HOSTNAME, MAX_LIFETIME, KEY, now=now - MAX_LIFETIME
    )

    result = run_verifier(key_file, [expired])

    assert result.stdout == "INVALID\n"


def test_verifier_rejects_cookie_expiring_beyond_maximum_future_lifetime(key_file):
    now = int(time.time())
    too_far_in_future = create_gatekeeper_cookie(
        HOSTNAME, MAX_LIFETIME + 10, KEY, now=now
    )

    result = run_verifier(key_file, [too_far_in_future])

    assert result.stdout == "INVALID\n"


def test_verifier_binds_signature_to_configured_hostname(key_file):
    now = int(time.time())
    cookie = create_gatekeeper_cookie(HOSTNAME, MAX_LIFETIME, KEY, now=now)

    result = run_verifier(key_file, [cookie], hostname="scholars.albany.edu")

    assert result.stdout == "INVALID\n"


def test_verifier_normalizes_hostname_and_rejects_non_ascii_input(key_file):
    now = int(time.time())
    cookie = create_gatekeeper_cookie(HOSTNAME, MAX_LIFETIME, KEY, now=now)
    mixed_case_host = run_verifier(key_file, [cookie], hostname="Archives.Albany.EDU")
    invalid_bytes = subprocess.run(
        [
            sys.executable,
            VERIFIER,
            str(key_file),
            HOSTNAME,
            str(MAX_LIFETIME),
        ],
        input=b"\xff\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )

    assert mixed_case_host.stdout == "VALID\n"
    assert invalid_bytes.returncode == 0
    assert invalid_bytes.stdout == b"INVALID" + os.linesep.encode("ascii")
    assert invalid_bytes.stderr == b""


def test_verifier_handles_multiple_lines_and_flushes_each_result(key_file):
    now = int(time.time())
    valid = create_gatekeeper_cookie(HOSTNAME, MAX_LIFETIME, KEY, now=now)
    process = subprocess.Popen(
        [sys.executable, VERIFIER, str(key_file), HOSTNAME, str(MAX_LIFETIME)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        bufsize=1,
    )
    try:
        process.stdin.write(valid + "\n")
        process.stdin.flush()
        assert process.stdout.readline() == "VALID\n"

        process.stdin.write("1\n")
        process.stdin.flush()
        assert process.stdout.readline() == "INVALID\n"
    finally:
        process.stdin.close()
        process.wait(timeout=10)

    assert process.returncode == 0
    assert process.stderr.read() == ""


def test_verifier_fails_closed_when_key_cannot_be_loaded(tmp_path):
    missing_key = tmp_path / "missing-key"

    result = run_verifier(missing_key, ["1"])

    assert result.returncode != 0
    assert result.stdout == ""
    assert "configuration error" in result.stderr


def test_verifier_rejects_invalid_key_file_without_exposing_values(tmp_path):
    invalid_key = tmp_path / "invalid-key"
    invalid_key.write_text("z" * 64, encoding="ascii")

    result = run_verifier(invalid_key, ["cookie-value"])

    assert result.returncode != 0
    assert result.stdout == ""
    assert "z" * 64 not in result.stderr
    assert "cookie-value" not in result.stderr
