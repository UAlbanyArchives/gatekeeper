import hashlib
import os
import queue
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest

from app.gatekeeper_cookie import create_observe_cookie


KEY_HEX = "0123456789abcdef" * 4
KEY = bytes.fromhex(KEY_HEX)
HOSTNAME = "archives.albany.edu"
MAX_LIFETIME = 1800
VERIFIER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "apache", "gatekeeper_observe_map.py")
)


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "signing-key"
    path.write_text(KEY_HEX + "\n", encoding="ascii")
    return path


def make_cookie(nonce="0123456789abcdef" * 2, now=None, ttl=MAX_LIFETIME):
    with patch("app.gatekeeper_cookie.secrets.token_hex", return_value=nonce):
        return create_observe_cookie(HOSTNAME, ttl, KEY, now=now)


def run_observer(key_file, data, hostname=HOSTNAME, max_lifetime=MAX_LIFETIME):
    return subprocess.run(
        [sys.executable, VERIFIER, str(key_file), hostname, str(max_lifetime)],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def test_observer_accepts_flask_cookie_and_hashes_ascii_nonce(key_file):
    nonce = "0123456789abcdef" * 2
    cookie = make_cookie(nonce)

    result = run_observer(key_file, (cookie + "\n").encode("ascii"), "Archives.Albany.EDU")

    session_id = hashlib.sha256(nonce.encode("ascii")).hexdigest()[:16]
    assert result.returncode == 0
    assert result.stdout.splitlines() == [("VALID:" + session_id).encode("ascii")]
    assert result.stderr == b""
    for secret in (cookie, nonce, cookie.split(".")[-1], KEY_HEX):
        assert secret.encode("ascii") not in result.stdout + result.stderr


def test_different_nonces_produce_different_session_ids(key_file):
    nonces = ["0" * 32, "1" * 32]
    cookies = [make_cookie(nonce) for nonce in nonces]
    result = run_observer(key_file, ("\n".join(cookies) + "\n").encode("ascii"))

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        ("VALID:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()[:16]).encode("ascii")
        for nonce in nonces
    ]
    assert len(set(result.stdout.splitlines())) == 2
    assert result.stderr == b""


@pytest.mark.parametrize(
    "cookie_factory",
    [
        lambda valid: "",
        lambda valid: "v2",
        lambda valid: "v1." + ".".join(valid.split(".")[1:]),
        lambda valid: "v2.invalid." + ".".join(valid.split(".")[2:]),
        lambda valid: valid.replace("v2.", "v2.0", 1),
        lambda valid: valid.replace(valid.split(".")[2], "A" * 32),
        lambda valid: valid.replace(valid.split(".")[2], "a" * 31),
        lambda valid: valid.replace(valid.split(".")[2], "a" * 32),
        lambda valid: valid[:-1] + ("0" if valid[-1] != "0" else "1"),
        lambda valid: "v2.{}.{}.{}".format(
            int(valid.split(".")[1]) + 1, valid.split(".")[2], valid.split(".")[3]
        ),
        lambda valid: valid + ".extra",
        lambda valid: "v2." + "9" * 5000 + "." + "a" * 32 + "." + "b" * 64,
    ],
)
def test_observer_rejects_malformed_or_modified_cookie(key_file, cookie_factory):
    cookie = cookie_factory(make_cookie())
    result = run_observer(key_file, (cookie + "\n").encode("ascii"))

    assert result.returncode == 0
    assert result.stdout.splitlines() == [b"INVALID"]
    assert result.stderr == b""


def test_observer_rejects_expired_and_future_cookies(key_file):
    now = int(time.time())
    expired = make_cookie(now=now - MAX_LIFETIME)
    future = make_cookie(now=now, ttl=MAX_LIFETIME + 30)

    result = run_observer(key_file, (expired + "\n" + future + "\n").encode("ascii"))

    assert result.returncode == 0
    assert result.stdout.splitlines() == [b"INVALID", b"INVALID"]
    assert result.stderr == b""


def test_observer_rejects_wrong_hostname_and_non_ascii_input(key_file):
    cookie = make_cookie()
    result = run_observer(
        key_file, cookie.encode("ascii") + b"\n\xff\n", hostname="other.example"
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == [b"INVALID", b"INVALID"]
    assert result.stderr == b""


def test_observer_flushes_each_response_before_input_closes(key_file):
    cookie = make_cookie()
    process = subprocess.Popen(
        [sys.executable, VERIFIER, str(key_file), HOSTNAME, str(MAX_LIFETIME)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    lines = queue.Queue()
    def read_responses():
        for _ in range(2):
            lines.put(process.stdout.readline())

    reader = threading.Thread(target=read_responses, daemon=True)
    try:
        reader.start()
        process.stdin.write((cookie + "\n").encode("ascii"))
        process.stdin.flush()
        assert lines.get(timeout=10).startswith(b"VALID:")
        process.stdin.write(b"invalid\n")
        process.stdin.flush()
        assert lines.get(timeout=10).strip() == b"INVALID"
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        assert process.stderr.read() == b""
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        reader.join(timeout=10)
        if not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()


@pytest.mark.parametrize("max_lifetime", ["0", "86401", "invalid"])
def test_observer_rejects_invalid_configuration_without_exposing_values(key_file, max_lifetime):
    cookie = make_cookie()
    result = run_observer(key_file, (cookie + "\n").encode("ascii"), max_lifetime=max_lifetime)

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"configuration error" in result.stderr
    assert cookie.encode("ascii") not in result.stderr
    assert KEY_HEX.encode("ascii") not in result.stderr


def test_observer_rejects_bad_key_without_exposing_contents(tmp_path):
    path = tmp_path / "bad-key"
    path.write_text("z" * 64, encoding="ascii")
    result = run_observer(path, b"cookie-value\n")

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"configuration error" in result.stderr
    assert b"z" * 64 not in result.stderr
    assert b"cookie-value" not in result.stderr
