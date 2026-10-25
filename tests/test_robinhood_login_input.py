import importlib.machinery
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).parents[1] / "deploy/bin/rsa-robinhood-login-input"


def load_helper():
    loader = importlib.machinery.SourceFileLoader("rsa_robinhood_login_input", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RobinhoodLoginInputTests(unittest.TestCase):
    def test_atomic_write_creates_exact_private_json(self) -> None:
        helper = load_helper()
        payload = {
            "version": 1,
            "broker": "robinhood",
            "passwords": [{"name": "primary", "password": "not-a-real-password"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "passwords.json"
            helper._atomic_write(path, payload, os.getuid(), os.getgid())
            self.assertEqual(json.loads(path.read_text()), payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(path.stat().st_gid, os.getgid())
            self.assertEqual(list(path.parent.glob(".passwords.json.*")), [])


if __name__ == "__main__":
    unittest.main()
