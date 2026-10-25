from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.brokerages import robinhood_credentials, robinhood_session
from src.brokerages.robinhood_credentials import (
    ACCOUNTS_FILE_ENV,
    LEGACY_CREDENTIALS_ENV,
    PASSWORD_FILE_ENV,
    SESSION_DIR_ENV,
    SESSION_TTL_ENV,
    RobinhoodCredentialError,
    load_robinhood_accounts,
    load_robinhood_passwords,
    load_session_ttl,
    parse_robinhood_accounts,
    parse_robinhood_passwords,
)
from src.brokerages.robinhood_session import RobinhoodBearerSession, RobinhoodSessionCache


def account_payload(*, username: str = "private-user@example.com", mfa: str = "workflow") -> bytes:
    return json.dumps({
        "version": 1,
        "broker": "robinhood",
        "accounts": [{"name": "primary", "username": username, "mfa": mfa}],
    }).encode()


def password_payload(*, password: str = "private-password") -> bytes:
    return json.dumps({
        "version": 1,
        "broker": "robinhood",
        "passwords": [{"name": "primary", "password": password}],
    }).encode()


class RobinhoodCredentialTests(unittest.TestCase):
    def test_account_and_password_representations_are_redacted(self) -> None:
        account = parse_robinhood_accounts(account_payload())[0]
        password = parse_robinhood_passwords(password_payload())["primary"]
        self.assertNotIn(account.username, repr(account))
        self.assertNotIn(password.password, repr(password))
        self.assertIn("primary", repr(account))

    def test_schema_rejects_unknown_duplicate_and_invalid_fields_without_echo(self) -> None:
        secret = "never-render-this-user"
        documents = [
            {"version": 2, "broker": "robinhood", "accounts": []},
            {"version": 1, "broker": "robinhood", "accounts": [{"name": "bad name", "username": secret, "mfa": "workflow"}]},
            {"version": 1, "broker": "robinhood", "accounts": [{"name": "one", "username": secret, "mfa": "seed"}]},
            {"version": 1, "broker": "robinhood", "accounts": [{"name": "one", "username": secret, "mfa": "workflow", "extra": secret}]},
        ]
        for document in documents:
            with self.subTest(document=document), self.assertRaises(RobinhoodCredentialError) as raised:
                parse_robinhood_accounts(json.dumps(document).encode())
            self.assertNotIn(secret, str(raised.exception))
        with self.assertRaises(RobinhoodCredentialError):
            parse_robinhood_accounts(b'{"version":1,"version":1,"broker":"robinhood","accounts":[]}')

    def test_durable_account_file_requires_absolute_owned_mode_0600_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "accounts.json")
            path.write_bytes(account_payload())
            path.chmod(0o640)
            with self.assertRaisesRegex(RobinhoodCredentialError, "permissions"):
                load_robinhood_accounts({ACCOUNTS_FILE_ENV: str(path)})
            path.chmod(0o600)
            accounts = load_robinhood_accounts({ACCOUNTS_FILE_ENV: str(path)})
            self.assertEqual(accounts[0].name, "primary")  # type: ignore[index]
            self.assertTrue(path.exists(), "durable username configuration must not be consumed")

    def test_one_time_password_regular_file_must_be_tmpfs_and_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.json")
            path.write_bytes(password_payload())
            path.chmod(0o600)
            with self.assertRaisesRegex(RobinhoodCredentialError, "tmpfs"):
                load_robinhood_passwords({"primary"}, {PASSWORD_FILE_ENV: str(path)})
            with mock.patch.object(robinhood_credentials, "is_tmpfs", return_value=True):
                passwords = load_robinhood_passwords({"primary"}, {PASSWORD_FILE_ENV: str(path)})
            self.assertEqual(passwords["primary"].password, "private-password")
            self.assertFalse(path.exists())

    def test_password_input_fails_if_it_cannot_be_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.json")
            path.write_bytes(password_payload())
            path.chmod(0o600)
            with (
                mock.patch.object(robinhood_credentials, "is_tmpfs", return_value=True),
                mock.patch.object(Path, "unlink", side_effect=PermissionError),
                self.assertRaisesRegex(RobinhoodCredentialError, "consume"),
            ):
                load_robinhood_passwords({"primary"}, {PASSWORD_FILE_ENV: str(path)})
            self.assertTrue(path.exists())

    def test_fifo_without_writer_times_out_and_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.fifo")
            os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(RobinhoodCredentialError, "timed out"):
                load_robinhood_passwords({"primary"}, {PASSWORD_FILE_ENV: str(path)}, fifo_timeout=0.01)
            self.assertFalse(path.exists())

    def test_missing_configured_password_input_is_ignored_when_cache_has_no_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.json")
            self.assertEqual(load_robinhood_passwords(set(), {PASSWORD_FILE_ENV: str(path)}), {})

    def test_supplied_password_input_is_consumed_even_when_cache_has_no_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.json")
            path.write_bytes(password_payload())
            path.chmod(0o600)
            with mock.patch.object(robinhood_credentials, "is_tmpfs", return_value=True):
                self.assertEqual(load_robinhood_passwords(set(), {PASSWORD_FILE_ENV: str(path)}), {})
            self.assertFalse(path.exists())

    def test_password_mapping_must_exactly_match_cache_misses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.json")
            path.write_bytes(password_payload())
            path.chmod(0o600)
            with mock.patch.object(robinhood_credentials, "is_tmpfs", return_value=True):
                with self.assertRaisesRegex(RobinhoodCredentialError, "does not match"):
                    load_robinhood_passwords({"other"}, {PASSWORD_FILE_ENV: str(path)})
            self.assertFalse(path.exists())

    def test_legacy_environment_always_fails_closed(self) -> None:
        secret = "user:password:totp"
        with self.assertRaises(RobinhoodCredentialError) as raised:
            load_robinhood_accounts({LEGACY_CREDENTIALS_ENV: secret})
        self.assertNotIn(secret, str(raised.exception))

    def test_session_ttl_default_and_bounds(self) -> None:
        self.assertEqual(load_session_ttl({}), 3600)
        self.assertEqual(load_session_ttl({SESSION_TTL_ENV: "300"}), 300)
        self.assertEqual(load_session_ttl({SESSION_TTL_ENV: "86400"}), 86400)
        for value in ("299", "86401", " 3600", "+3600", "3.6e3", "invalid"):
            with self.subTest(value=value), self.assertRaises(RobinhoodCredentialError):
                load_session_ttl({SESSION_TTL_ENV: value})


class RobinhoodSessionCacheTests(unittest.TestCase):
    def make_cache(self, directory: str, now: list[float]) -> RobinhoodSessionCache:
        with mock.patch.object(robinhood_session, "is_tmpfs", return_value=True):
            return RobinhoodSessionCache.from_environment({SESSION_DIR_ENV: directory}, wall_clock=lambda: now[0])

    def test_cache_is_mode_protected_and_contains_only_bearer_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            now = [1000.0]
            cache = self.make_cache(directory, now)
            session = RobinhoodBearerSession("Bearer", "private-access-token", 4600.0)
            cache.save("primary", "private-user@example.com", session)
            files = list(Path(directory).iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            document = json.loads(files[0].read_text())
            self.assertEqual(set(document), {"version", "token_type", "access_token", "expires_at"})
            self.assertNotIn("refresh", files[0].read_text())
            self.assertNotIn("device", files[0].read_text())
            self.assertEqual(cache.load("primary", "private-user@example.com"), session)
            self.assertNotIn("private-access-token", repr(session))

    def test_expired_cache_is_removed_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            now = [1000.0]
            cache = self.make_cache(directory, now)
            cache.save("primary", "user", RobinhoodBearerSession("Bearer", "token", 1001.0))
            now[0] = 1001.0
            self.assertIsNone(cache.load("primary", "user"))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cache_directory_requires_protection_and_tmpfs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o750)
            with self.assertRaisesRegex(RobinhoodCredentialError, "permissions"):
                self.make_cache(directory, [0.0])
            Path(directory).chmod(0o700)
            with self.assertRaisesRegex(RobinhoodCredentialError, "tmpfs"):
                RobinhoodSessionCache.from_environment({SESSION_DIR_ENV: directory}, wall_clock=lambda: 0.0)

    def test_invalid_cache_never_returns_bearer_state(self) -> None:
        invalid_documents = [
            {"access_token": "secret", "refresh_token": "forbidden"},
            {"version": 1, "token_type": "Bearer", "access_token": "token\nInjected: value", "expires_at": 1000},
            {"version": 1, "token_type": "Basic", "access_token": "token", "expires_at": 1000},
            {"version": 1, "token_type": "Bearer", "access_token": "token", "expires_at": float("nan")},
            {"version": 1, "token_type": "Bearer", "access_token": "token", "expires_at": float("inf")},
            {"version": 1, "token_type": "Bearer", "access_token": "token", "expires_at": 999999},
        ]
        for document in invalid_documents:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as directory:
                Path(directory).chmod(0o700)
                cache = self.make_cache(directory, [0.0])
                path = cache._path("primary", "user")  # noqa: SLF001
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                with self.assertRaisesRegex(RobinhoodCredentialError, "Invalid"):
                    cache.load("primary", "user")
                self.assertFalse(path.exists())
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            cache = self.make_cache(directory, [0.0])
            path = cache._path("primary", "user")  # noqa: SLF001
            path.write_text('{"version":1,"token_type":"Bearer","token_type":"Bearer","access_token":"token","expires_at":1000}')
            path.chmod(0o600)
            with self.assertRaisesRegex(RobinhoodCredentialError, "Invalid"):
                cache.load("primary", "user")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
