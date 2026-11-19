import hashlib
import hmac
import os
import re
import time


_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}\Z")


def load_signing_key(path):
    if not path:
        raise ValueError("GATEKEEPER_KEY_FILE must be configured")

    try:
        if not os.path.isfile(path):
            raise ValueError("GATEKEEPER_KEY_FILE must be a readable regular file")
        with open(path, "r", encoding="ascii") as key_file:
            encoded_key = key_file.read().strip()
    except (OSError, UnicodeError):
        raise ValueError("GATEKEEPER_KEY_FILE must be a readable regular file") from None

    if not _HEX_KEY.fullmatch(encoded_key):
        raise ValueError("GATEKEEPER_KEY_FILE must contain exactly 64 hexadecimal characters")

    key = bytes.fromhex(encoded_key)
    if len(key) != 32:
        raise ValueError("GATEKEEPER_KEY_FILE must decode to exactly 32 bytes")
    return key


def load_gatekeeper_config(environ=None):
    environ = os.environ if environ is None else environ
    key_path = environ.get("GATEKEEPER_KEY_FILE")
    hostname = environ.get("GATEKEEPER_HOSTNAME", "").strip().lower()
    ttl_value = environ.get("GATEKEEPER_COOKIE_TTL")

    if not key_path:
        raise ValueError("GATEKEEPER_KEY_FILE must be configured")
    if not hostname:
        raise ValueError("GATEKEEPER_HOSTNAME must be configured")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("GATEKEEPER_HOSTNAME must be ASCII") from None
    if ttl_value is None:
        raise ValueError("GATEKEEPER_COOKIE_TTL must be configured")
    try:
        ttl = int(ttl_value)
    except (TypeError, ValueError):
        raise ValueError("GATEKEEPER_COOKIE_TTL must be an integer") from None
    if not 1 <= ttl <= 86400:
        raise ValueError("GATEKEEPER_COOKIE_TTL must be between 1 and 86400 seconds")

    return load_signing_key(key_path), hostname, ttl


def create_gatekeeper_cookie(hostname, ttl, key, now=None):
    expiry = int(time.time() if now is None else now) + ttl
    message = "{}|v1|{}".format(hostname.lower(), expiry).encode("ascii")
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return "v1.{}.{}".format(expiry, signature)
