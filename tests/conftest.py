import os
import tempfile
from pathlib import Path


_test_key_directory = tempfile.TemporaryDirectory(prefix="gatekeeper-tests-")
_test_key_path = Path(_test_key_directory.name) / "signing-key"
_test_key_path.write_text("0123456789abcdef" * 4 + "\n", encoding="ascii")

os.environ["GATEKEEPER_KEY_FILE"] = str(_test_key_path)
os.environ["GATEKEEPER_HOSTNAME"] = "Archives.Albany.edu"
os.environ["GATEKEEPER_COOKIE_TTL"] = "1800"
