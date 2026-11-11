#!/usr/bin/python3
import sys

from gatekeeper_cookie import parse_key, parse_lifetime, validate_cookie


def main():
    if len(sys.argv) != 4:
        print("Usage: gatekeeper_map.py KEY_FILE HOSTNAME MAX_LIFETIME", file=sys.stderr)
        return 2
    key_path, hostname, lifetime = sys.argv[1:]
    try:
        with open(key_path, "r", encoding="ascii") as key_file:
            key = parse_key(key_file.read().strip())
        lifetime = parse_lifetime(lifetime)
        hostname.encode("ascii")
        if not hostname or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in hostname):
            raise ValueError("Hostname must be lowercase ASCII DNS name")
    except (OSError, ValueError, UnicodeError) as error:
        print("Gatekeeper verifier configuration error: {}".format(error), file=sys.stderr)
        return 2

    for line in sys.stdin.buffer:
        try:
            token = line.rstrip(b"\n").decode("ascii")
        except UnicodeDecodeError:
            token = ""
        session_id = validate_cookie(key, hostname, token, lifetime)
        print("VALID" if session_id else "INVALID", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
