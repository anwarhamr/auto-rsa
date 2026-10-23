from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import traceback
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from src.brokerages import chase_credentials
from src.brokerages.chase_credentials import (
    ALLOW_DURABLE_PROFILE_ENV,
    ALLOW_LEGACY_ENV,
    CREDENTIALS_FILE_ENV,
    DURABLE_PROFILE_DIR_ENV,
    ChaseCredential,
    ChaseCredentialError,
    chase_profile_directory,
    load_chase_credentials,
    parse_chase_credentials,
)


def payload(*, debug: bool = False, phone: str = "1234") -> bytes:
    return json.dumps(
        {
            "version": 1,
            "broker": "chase",
            "accounts": [
                {
                    "username": "secret-user",
                    "password": "secret-password",
                    "phone_last_four": phone,
                    "debug": debug,
                }
            ],
        }
    ).encode()


class ChaseCredentialTests(unittest.TestCase):
    def test_schema_builds_typed_redacted_credentials(self) -> None:
        credential = parse_chase_credentials(payload())[0]
        self.assertIsInstance(credential, ChaseCredential)
        self.assertFalse(credential.debug)
        self.assertEqual(credential.phone_last_four, "1234")
        rendered = repr(credential)
        self.assertNotIn("secret-user", rendered)
        self.assertNotIn("secret-password", rendered)
        self.assertNotIn("1234", rendered)

    def test_schema_rejects_version_unknown_fields_and_phone(self) -> None:
        cases = [
            {"version": 2, "broker": "chase", "accounts": []},
            {"version": 1, "broker": "chase", "accounts": [], "extra": "secret"},
            json.loads(payload(phone="12x4")),
        ]
        for document in cases:
            with self.subTest(document=document), self.assertRaises(ChaseCredentialError) as raised:
                parse_chase_credentials(json.dumps(document).encode())
            self.assertNotIn("secret-password", str(raised.exception))

    def test_invalid_json_error_does_not_echo_secret_source(self) -> None:
        secret = "never-echo-this-password"
        try:
            parse_chase_credentials(f'{{"password":"{secret}"'.encode())
        except ChaseCredentialError as exc:
            rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        else:
            self.fail("invalid JSON was accepted")
        self.assertNotIn(secret, rendered)

    def test_regular_input_rejects_group_or_other_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_bytes(payload())
            path.chmod(0o640)
            with self.assertRaisesRegex(ChaseCredentialError, "permissions"):
                load_chase_credentials({CREDENTIALS_FILE_ENV: str(path)})
            self.assertTrue(path.exists(), "unaccepted input must not be removed")

    def test_input_rejects_foreign_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_bytes(payload())
            path.chmod(0o600)
            real_lstat = os.lstat

            def foreign_lstat(candidate: str | os.PathLike[str]) -> os.stat_result:
                current = real_lstat(candidate)
                values = list(current)
                values[4] = current.st_uid + 1
                return os.stat_result(values)

            with mock.patch.object(chase_credentials.os, "lstat", side_effect=foreign_lstat):
                with self.assertRaisesRegex(ChaseCredentialError, "owned"):
                    load_chase_credentials({CREDENTIALS_FILE_ENV: str(path)})
            self.assertTrue(path.exists(), "unaccepted input must not be removed")

    def test_regular_tmpfs_input_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_bytes(payload())
            path.chmod(0o600)
            with mock.patch.object(chase_credentials, "_is_tmpfs", return_value=True):
                credentials = load_chase_credentials({CREDENTIALS_FILE_ENV: str(path)})
            self.assertEqual(len(credentials or ()), 1)
            self.assertFalse(path.exists())

    def test_input_size_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_bytes(b"x" * (chase_credentials.MAX_CREDENTIAL_BYTES + 1))
            path.chmod(0o600)
            with mock.patch.object(chase_credentials, "_is_tmpfs", return_value=True):
                with self.assertRaisesRegex(ChaseCredentialError, "size limit"):
                    load_chase_credentials({CREDENTIALS_FILE_ENV: str(path)})

    def test_legacy_env_fails_closed_unless_explicitly_enabled(self) -> None:
        legacy = "secret-user:secret-password:1234:False"
        with self.assertRaises(ChaseCredentialError) as raised:
            load_chase_credentials({"CHASE": legacy})
        self.assertNotIn("secret-password", str(raised.exception))

        credentials = load_chase_credentials({"CHASE": legacy, ALLOW_LEGACY_ENV: "true"})
        self.assertIsNotNone(credentials)
        self.assertFalse(credentials[0].debug)  # type: ignore[index]

    def test_ephemeral_profile_is_removed_after_use(self) -> None:
        with chase_profile_directory({}) as profile:
            profile_path = Path(profile)
            self.assertTrue(profile_path.is_dir())
            self.assertEqual(profile_path.stat().st_mode & 0o777, 0o700)
        self.assertFalse(profile_path.exists())

    def test_durable_profile_requires_opt_in_and_protected_absolute_dir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            path.chmod(0o700)
            with self.assertRaises(ChaseCredentialError):
                with chase_profile_directory({DURABLE_PROFILE_DIR_ENV: str(path)}):
                    pass
            with chase_profile_directory(
                {ALLOW_DURABLE_PROFILE_ENV: "true", DURABLE_PROFILE_DIR_ENV: str(path)}
            ) as selected:
                self.assertEqual(selected, str(path))
            path.chmod(0o750)
            with self.assertRaisesRegex(ChaseCredentialError, "permissions"):
                with chase_profile_directory(
                    {ALLOW_DURABLE_PROFILE_ENV: "true", DURABLE_PROFILE_DIR_ENV: str(path)}
                ):
                    pass

    def test_chase_init_passes_typed_false_debug_and_selected_profile(self) -> None:
        calls: dict[str, object] = {}

        class FakeSession:
            def __init__(self, **kwargs: object) -> None:
                calls.update(kwargs)

            def login(self, username: str, password: str, phone: int) -> bool:
                calls["login"] = (username, password, phone)
                if calls.get("raise"):
                    raise RuntimeError(f"broker echoed {username} {password}")
                return False

            def close_browser(self) -> None:
                pass

        class FakeAllAccount:
            def __init__(self, session: object) -> None:
                self.account_connectors = {}

        class FakeBrokerage:
            def __init__(self, name: str) -> None:
                self.name = name

            def set_logged_in_object(self, *args: object) -> None:
                pass

        chase_module = types.ModuleType("chase")
        account_module = types.ModuleType("chase.account")
        account_module.AllAccount = FakeAllAccount
        account_module.AccountDetails = object
        order_module = types.ModuleType("chase.order")
        order_module.PriceType = object
        order_module.OrderSide = object
        order_module.Order = object
        session_module = types.ModuleType("chase.session")
        session_module.ChaseSession = FakeSession
        symbols_module = types.ModuleType("chase.symbols")
        symbols_module.SymbolQuote = object
        symbols_module.SymbolHoldings = object
        chase_module.account = account_module
        chase_module.order = order_module
        chase_module.session = session_module
        chase_module.symbols = symbols_module

        commands_module = types.ModuleType("discord.ext.commands")
        commands_module.Bot = object
        ext_module = types.ModuleType("discord.ext")
        ext_module.commands = commands_module
        discord_module = types.ModuleType("discord")
        discord_module.ext = ext_module
        dotenv_module = types.ModuleType("dotenv")
        dotenv_module.load_dotenv = lambda: None
        helper_module = types.ModuleType("src.helper_api")
        helper_module.Brokerage = FakeBrokerage
        helper_module.StockOrder = object
        helper_module.get_otp_from_discord = object
        helper_module.print_all_holdings = object
        helper_module.print_and_discord = object

        modules = {
            "chase": chase_module,
            "chase.account": account_module,
            "chase.order": order_module,
            "chase.session": session_module,
            "chase.symbols": symbols_module,
            "discord": discord_module,
            "discord.ext": ext_module,
            "discord.ext.commands": commands_module,
            "dotenv": dotenv_module,
            "src.helper_api": helper_module,
        }
        sys.modules.pop("src.brokerages.chase_api", None)
        with mock.patch.dict(sys.modules, modules):
            from src.brokerages import chase_api

            result = chase_api.chase_init(
                ChaseCredential("secret-user", "secret-password", "1234", False),
                1,
                profile_path="/ephemeral/profile",
            )
        self.assertIsNotNone(result)
        self.assertIs(calls["debug"], False)
        self.assertEqual(calls["profile_path"], "/ephemeral/profile")

        calls["raise"] = True
        output = io.StringIO()
        with redirect_stdout(output):
            failed = chase_api.chase_init(
                ChaseCredential("secret-user", "secret-password", "1234", False),
                1,
                profile_path="/ephemeral/profile",
            )
        self.assertIsNone(failed)
        self.assertNotIn("secret-user", output.getvalue())
        self.assertNotIn("secret-password", output.getvalue())


if __name__ == "__main__":
    unittest.main()
