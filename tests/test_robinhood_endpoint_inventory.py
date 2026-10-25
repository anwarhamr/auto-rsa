from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import robin_stocks

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "deploy" / "egress"
INVENTORY_PATH = POLICY_DIR / "robinhood-endpoints.json"
ALLOW_PATH = POLICY_DIR / "robinhood-endpoints.allow"
ROBIN_STOCKS_REVISION = "1ba446970f7bac5c4c0ac96390ae9e3f7a9b9d0e"
HOST_PATTERN = re.compile(r"https://([a-z0-9.-]+)", re.IGNORECASE)


class RobinhoodEndpointInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    def test_inventory_classifies_every_dependency_robinhood_host(self) -> None:
        package_dir = Path(robin_stocks.__file__).resolve().parent / "robinhood"
        application_dir = ROOT / "src" / "brokerages"
        discovered: set[str] = set()
        sources = [*package_dir.rglob("*.py"), *application_dir.glob("robinhood*.py")]
        for source in sources:
            for host in HOST_PATTERN.findall(source.read_text(encoding="utf-8")):
                normalized = host.lower()
                if normalized.endswith(".robinhood.com"):
                    discovered.add(normalized)

        allowed = {entry["host"] for entry in self.inventory["allowed"]}
        denied = {entry["host"] for entry in self.inventory["classified_denied"]}
        self.assertEqual(discovered, allowed | denied)
        self.assertFalse(allowed & denied)

    def test_initial_allowlist_is_exact_and_tls_only(self) -> None:
        self.assertEqual(
            self.inventory["allowed"],
            [
                {
                    "host": "api.robinhood.com",
                    "port": 443,
                    "reason": "Current login, phone-app verification, account, holdings, quote, and equity-order flows",
                }
            ],
        )
        allow_lines = [line for line in ALLOW_PATH.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(allow_lines, ["api.robinhood.com"])

    def test_inventory_is_bound_to_locked_dependency_revision(self) -> None:
        self.assertEqual(self.inventory["dependency"]["revision"], ROBIN_STOCKS_REVISION)
        lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
        self.assertIn(f"robin_stocks_v2?rev={ROBIN_STOCKS_REVISION}#{ROBIN_STOCKS_REVISION}", lock)


if __name__ == "__main__":
    unittest.main()
