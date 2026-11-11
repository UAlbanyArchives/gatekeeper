import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from gatekeeper_cookie import issue_cookie, parse_key


ROOT = Path(__file__).resolve().parent.parent
KEY_HEX = "ab" * 32


class MapTests(unittest.TestCase):
    def test_persistent_map_accepts_only_valid_cookies(self):
        key = parse_key(KEY_HEX)
        now = int(time.time())
        valid = issue_cookie(key, "archives.albany.edu", 1800, now=now)
        expired = issue_cookie(key, "archives.albany.edu", 30, now=now - 30)
        other_host = issue_cookie(key, "scholars.albany.edu", 1800, now=now)
        too_long = issue_cookie(key, "archives.albany.edu", 1801, now=now)
        values = [b"1", valid.encode(), expired.encode(), other_host.encode(),
                  too_long.encode(), b"\xff", valid.encode()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            path.write_text(KEY_HEX, encoding="ascii")
            env = dict(os.environ, PYTHONPATH=str(ROOT))
            result = subprocess.run(
                [sys.executable, str(ROOT / "apache" / "gatekeeper_map.py"),
                 str(path), "archives.albany.edu", "1800"],
                input=b"\n".join(values) + b"\n", stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [b"INVALID", b"VALID", b"INVALID", b"INVALID", b"INVALID", b"INVALID", b"VALID"],
        )

    def test_missing_secret_fails_at_startup(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        result = subprocess.run(
            [sys.executable, str(ROOT / "apache" / "gatekeeper_map.py"),
             str(ROOT / "missing-key"), "archives.albany.edu", "1800"],
            input=b"1\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"configuration error", result.stderr)


if __name__ == "__main__":
    unittest.main()
