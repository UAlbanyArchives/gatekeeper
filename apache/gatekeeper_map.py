#!/usr/bin/env python3
import hashlib
import hmac
import os
import re
import sys
import time


_COOKIE_PATTERN = re.compile(r"v1\.([0-9]+)\.([0-9a-f]{64})\Z")
_KEY_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
_MAX_COOKIE_LENGTH = 80


def load_key(path):
    if not os.path.isfile(path):
        raise ValueError("Signing key must be a readable regular file")
    try:
        with open(path, "r", encoding="ascii") as key_file:
            encoded_key = key_file.read().strip()
    except (OSError, UnicodeError):
        raise ValueError("Signing key must be a readable regular file")
    if not _KEY_PATTERN.fullmatch(encoded_key):
        raise ValueError("Signing key must contain exactly 64 hexadecimal characters")
    key = bytes.fromhex(encoded_key)
    if len(key) != 32:
        raise ValueError("Signing key must decode to exactly 32 bytes")
    return key


def parse_max_lifetime(value):
    try:
        lifetime = int(value)
    except (TypeError, ValueError):
        raise ValueError("Maximum cookie lifetime must be an integer")
    if not 1 <= lifetime <= 86400:
        raise ValueError("Maximum cookie lifetime must be between 1 and 86400 seconds")
    return lifetime


def validate_cookie(cookie, hostname, key, max_lifetime, now=None):
    if not cookie or len(cookie) > _MAX_COOKIE_LENGTH:
        return False
    match = _COOKIE_PATTERN.fullmatch(cookie)
    if not match:
        return False

    expiry = int(match.group(1))
    current_time = int(time.time() if now is None else now)
    if expiry <= current_time or expiry > current_time + max_lifetime:
        return False

    message = "{}|v1|{}".format(hostname.lower(), expiry).encode("ascii")
    expected_signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(match.group(2), expected_signature)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print(
            "Usage: gatekeeper_map.py SIGNING_KEY_FILE HOSTNAME MAX_LIFETIME",
            file=sys.stderr,
        )
        return 2

    key_path, hostname, lifetime_value = argv
    try:
        key = load_key(key_path)
        hostname = hostname.lower()
        hostname.encode("ascii")
        if not hostname:
            raise ValueError("Hostname must not be empty")
        max_lifetime = parse_max_lifetime(lifetime_value)
    except (OSError, UnicodeError, ValueError) as error:
        print("Gatekeeper verifier configuration error: {}".format(error), file=sys.stderr)
        return 2

    for line in sys.stdin.buffer:
        try:
            cookie = line.rstrip(b"\r\n").decode("ascii")
            valid = validate_cookie(cookie, hostname, key, max_lifetime)
        except (UnicodeError, ValueError, OverflowError):
            valid = False
        print("VALID" if valid else "INVALID", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
