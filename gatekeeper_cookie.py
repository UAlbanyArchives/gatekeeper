import hashlib
import hmac
import re
import secrets
import time


COOKIE_NAME = "turnstile_verified"
DEFAULT_LIFETIME = 1800
MAX_LIFETIME = 86400
_TOKEN = re.compile(r"^v1\.([0-9]{1,12})\.([0-9]{1,12})\.([0-9a-f]{32})\.([0-9a-f]{64})$")
_KEY = re.compile(r"^[0-9a-fA-F]{64,}$")


def parse_key(value):
    if not _KEY.fullmatch(value) or len(value) % 2:
        raise ValueError("Signing key must be at least 64 hexadecimal characters")
    return bytes.fromhex(value)


def parse_lifetime(value):
    try:
        lifetime = int(value)
    except (ValueError, TypeError):
        raise ValueError("Cookie lifetime must be an integer in seconds")
    if not 1 <= lifetime <= MAX_LIFETIME:
        raise ValueError("Cookie lifetime must be between 1 and 86400 seconds")
    return lifetime


def _signature(key, hostname, payload):
    message = (hostname.lower() + "|" + payload).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def issue_cookie(key, hostname, lifetime, now=None):
    issued = int(time.time() if now is None else now)
    payload = "v1.{}.{}.{}".format(issued, issued + lifetime, secrets.token_hex(16))
    return payload + "." + _signature(key, hostname, payload)


def validate_cookie(key, hostname, value, max_lifetime, now=None):
    match = _TOKEN.fullmatch(value)
    if not match:
        return None
    issued, expires = int(match.group(1)), int(match.group(2))
    current = int(time.time() if now is None else now)
    if issued > current or expires <= current or expires <= issued:
        return None
    if expires - issued > max_lifetime:
        return None
    payload, signature = value.rsplit(".", 1)
    expected = _signature(key, hostname, payload)
    if not hmac.compare_digest(signature, expected):
        return None
    return match.group(3)
