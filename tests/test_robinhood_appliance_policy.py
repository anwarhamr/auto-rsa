from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.robinhood.yml"
POLICY_DIR = ROOT / "deploy" / "egress"


class RobinhoodAppliancePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            accounts = root / "accounts.json"
            accounts.write_text("{}", encoding="utf-8")
            runtime = root / "runtime"
            runtime.mkdir()
            environment = os.environ | {
                "RSA_IMAGE": f"registry.invalid/auto-rsa@sha256:{'a' * 64}",
                "RSA_EGRESS_IMAGE": f"registry.invalid/rsa-egress@sha256:{'b' * 64}",
                "RSA_ROBINHOOD_ACCOUNTS_FILE_HOST": str(accounts),
                "RSA_ROBINHOOD_RUNTIME_DIR": str(runtime),
            }
            result = subprocess.run(
                ["docker", "compose", "--profile", "run", "-f", str(COMPOSE), "config", "--format", "json"],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
        cls.rendered_text = result.stdout
        cls.rendered = json.loads(result.stdout)

    def test_stack_has_only_gateway_and_one_shot_trader(self) -> None:
        self.assertEqual(set(self.rendered["services"]), {"robinhood-egress", "trader"})
        lowered = self.rendered_text.lower()
        for forbidden in ("discord.com", "watchtower", "/var/run/docker.sock", "host.docker.internal"):
            self.assertNotIn(forbidden, lowered)

    def test_no_service_has_inbound_or_host_network_configuration(self) -> None:
        for service in self.rendered["services"].values():
            self.assertNotIn("ports", service)
            self.assertNotIn("expose", service)
            self.assertNotEqual(service.get("network_mode"), "host")
        self.assertEqual(self.rendered["services"]["trader"]["network_mode"], "service:robinhood-egress")

    def test_trader_is_fixed_nonroot_and_hardened(self) -> None:
        trader = self.rendered["services"]["trader"]
        self.assertEqual(trader["user"], "10001:10001")
        self.assertTrue(trader["read_only"])
        self.assertIn("ALL", trader["cap_drop"])
        self.assertIn("no-new-privileges:true", trader["security_opt"])
        self.assertEqual(trader["entrypoint"], ["auto_rsa_bot"])
        self.assertEqual(trader["environment"]["RSA_DISABLE_UPDATE_CHECK"], "true")
        self.assertEqual(trader["environment"]["RSA_ROBINHOOD_ORDER_ACCOUNT_TYPE"], "")
        self.assertEqual(trader["environment"]["DISCORD_TOKEN"], "")
        self.assertEqual(trader["environment"]["ROBINHOOD"], "")
        self.assertEqual(trader["environment"]["HTTPS_PROXY"], "http://127.0.0.1:3128")
        self.assertEqual(trader["environment"]["NO_PROXY"], "")

    def test_gateway_has_only_network_admin_during_policy_setup(self) -> None:
        gateway = self.rendered["services"]["robinhood-egress"]
        self.assertTrue(gateway["read_only"])
        self.assertEqual(set(gateway["cap_add"]), {"NET_ADMIN", "SETGID", "SETPCAP", "SETUID"})
        self.assertIn("ALL", gateway["cap_drop"])
        self.assertIn("no-new-privileges:true", gateway["security_opt"])

    def test_deployed_images_are_required_to_be_immutable_and_preloaded(self) -> None:
        for service in self.rendered["services"].values():
            self.assertRegex(service["image"], r"@sha256:[0-9a-f]{64}$")
            self.assertEqual(service["pull_policy"], "never")

    def test_nft_policy_denies_direct_and_bypass_protocols(self) -> None:
        policy = (POLICY_DIR / "nftables.conf").read_text(encoding="utf-8")
        self.assertGreaterEqual(policy.count("policy drop;"), 2)
        self.assertIn("meta skuid 10001 ip daddr 127.0.0.1 tcp dport 3128 accept", policy)
        self.assertNotIn("meta skuid 10001 udp", policy)
        self.assertNotIn("meta skuid 10001 tcp dport 443", policy)
        self.assertIn("meta skuid 10002 ip daddr @blocked_ipv4 drop", policy)
        self.assertLess(
            policy.index("meta skuid 10002 ip daddr @blocked_ipv4 drop"),
            policy.index("meta skuid 10002 meta nfproto ipv4 tcp dport 443 accept"),
        )
        for blocked in ("10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"):
            self.assertIn(blocked, policy)
        self.assertNotIn("dport 853 accept", policy)
        self.assertNotIn("udp dport 443 accept", policy)
        self.assertNotIn("meta skuid 10002 tcp dport 443 accept", policy)
        self.assertIn("meta skuid 10002 meta nfproto ipv4 tcp dport 443 accept", policy)
        self.assertIn("meta skuid 10002 ip daddr 127.0.0.11 meta l4proto udp accept", policy)
        self.assertIn('iifname "lo" ip daddr 127.0.0.11 meta l4proto udp accept', policy)
        self.assertIn('iifname "lo" ip saddr 127.0.0.11 udp sport 53 accept', policy)

    def test_gateway_fails_closed_when_proxy_uid_cannot_resolve(self) -> None:
        entrypoint = (POLICY_DIR / "entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("--reuid=10002", entrypoint)
        self.assertIn("gethostbyname(q(api.robinhood.com))", entrypoint)

    def test_proxy_is_connect_only_exact_host_and_port(self) -> None:
        proxy = (POLICY_DIR / "squid.conf").read_text(encoding="utf-8")
        self.assertIn("http_port 127.0.0.1:3128", proxy)
        self.assertIn("http_access deny !CONNECT", proxy)
        self.assertIn("acl TLS_port port 443", proxy)
        self.assertIn("http_access deny numeric_target", proxy)
        self.assertIn("http_access allow reviewed_robinhood", proxy)
        self.assertTrue(proxy.rstrip().endswith("via off"))

    def test_application_image_declares_fixed_trader_uid(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("useradd --uid 10001", dockerfile)
        self.assertIn("USER appuser", dockerfile)


if __name__ == "__main__":
    unittest.main()
