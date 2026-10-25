from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from src.brokerages import robinhood_api
from src.brokerages.robinhood_api import RobinhoodRunError, robinhood_run
from src.brokerages.robinhood_credentials import RobinhoodAccount, RobinhoodPassword
from src.brokerages.robinhood_session import RobinhoodBearerSession


class _Order:
    def __init__(self, *, holdings: bool = False, dry: bool = True) -> None:
        self.holdings = holdings
        self.dry = dry

    def get_holdings(self) -> bool:
        return self.holdings

    def get_dry(self) -> bool:
        return self.dry

    def get_stocks(self) -> list[str]:
        return ["TEST"]

    def get_action(self) -> str:
        return "buy"

    def get_amount(self) -> float:
        return 1.0


class _Cache:
    def __init__(self, session: RobinhoodBearerSession | None) -> None:
        self.session = session
        self.saved: list[RobinhoodBearerSession] = []
        self.removed = 0

    def load(self, _name: str, _username: str) -> RobinhoodBearerSession | None:
        return self.session

    def save(self, _name: str, _username: str, session: RobinhoodBearerSession) -> None:
        self.saved.append(session)

    def remove(self, _name: str, _username: str) -> None:
        self.removed += 1


class _Auth:
    def __init__(self, session: RobinhoodBearerSession) -> None:
        self.session = session
        self.authenticated = 0
        self.activated = 0
        self.cleared = 0
        self.inputs: list[tuple[str, str, int, str | None, float]] = []

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        ttl: int,
        callbacks: object,
        mfa_code: str | None = None,
        verification_timeout: float = 300.0,
    ) -> RobinhoodBearerSession:
        self.authenticated += 1
        self.inputs.append((username, password, ttl, mfa_code, verification_timeout))
        return self.session

    def activate(self, session: RobinhoodBearerSession) -> None:
        self.activated += 1
        self.session = session

    def clear(self) -> None:
        self.cleared += 1


class _Client:
    def __init__(self, profile: object | None = None, positions: object | None = None, order_response: object | None = None) -> None:
        self.profile = profile if profile is not None else [{"account_number": "12345678", "portfolio_cash": "100.00", "brokerage_account_type": "cash"}]
        self.positions_response = [] if positions is None else positions
        self.order_response = {"id": "order-id"} if order_response is None else order_response
        self.order_calls = 0

    def account_profile(self) -> object:
        return self.profile

    def positions(self, _account_number: str) -> object:
        return self.positions_response

    def symbol(self, _instrument_url: str) -> object:
        return "TEST"

    def latest_price(self, _symbol: str, _price_type: str | None = None) -> object:
        return ["10.00"]

    def order(self, **_kwargs: object) -> object:
        self.order_calls += 1
        return self.order_response


class RobinhoodRunTests(unittest.TestCase):
    def run_with(
        self,
        *,
        account: RobinhoodAccount,
        cache: _Cache,
        auth: _Auth,
        client: _Client,
        order: _Order | None = None,
        bot: object | None = None,
        password_loader: object | None = None,
        code_reader: object | None = None,
        now: float = 1000.0,
        monotonic: object | None = None,
    ) -> str:
        output = io.StringIO()
        password_loader = password_loader or (lambda _names, _environment: {"primary": RobinhoodPassword("primary", "private-password")})
        code_reader = code_reader or (lambda _kind, _timeout: "654321")
        with (
            mock.patch.object(robinhood_api, "load_robinhood_accounts", return_value=(account,)),
            mock.patch.object(robinhood_api, "load_session_ttl", return_value=3600),
            mock.patch.object(robinhood_api, "load_robinhood_passwords", side_effect=password_loader),
            mock.patch.object(robinhood_api.RobinhoodSessionCache, "from_environment", return_value=cache),
            redirect_stdout(output),
        ):
            robinhood_run(
                order or _Order(),  # type: ignore[arg-type]
                bot_obj=bot,  # type: ignore[arg-type]
                environ={},
                authenticator=auth,  # type: ignore[arg-type]
                client=client,  # type: ignore[arg-type]
                code_reader=code_reader,  # type: ignore[arg-type]
                wall_clock=lambda: now,
                monotonic=monotonic or (lambda: 0.0),  # type: ignore[arg-type]
            )
        return output.getvalue()

    def test_fresh_password_is_used_once_and_session_is_saved_before_immediate_execution(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "workflow")
        session = RobinhoodBearerSession("Bearer", "access", 4600.0)
        cache = _Cache(None)
        auth = _Auth(session)
        output = self.run_with(account=account, cache=cache, auth=auth, client=_Client())
        self.assertEqual(auth.authenticated, 1)
        self.assertEqual(auth.inputs, [("private-user", "private-password", 3600, None, 300.0)])
        self.assertEqual(cache.saved, [session])
        self.assertGreaterEqual(auth.cleared, 1)
        self.assertNotIn("private-user", output)
        self.assertNotIn("private-password", output)
        self.assertNotIn("access", output)

    def test_valid_cache_activates_bearer_without_password_or_login_replay(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "workflow")
        session = RobinhoodBearerSession("Bearer", "cached-access", 4600.0)
        cache = _Cache(session)
        auth = _Auth(session)

        def password_loader(names: object, _environment: object) -> object:
            self.assertEqual(names, set(), "valid cache must not request any password")
            return {}

        output = self.run_with(account=account, cache=cache, auth=auth, client=_Client(), password_loader=password_loader)
        self.assertEqual(auth.authenticated, 0)
        self.assertEqual(auth.activated, 1)
        self.assertNotIn("cached-access", output)

    def test_totp_collection_shares_the_single_verification_deadline(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "totp")
        session = RobinhoodBearerSession("Bearer", "access", 4600.0)
        auth = _Auth(session)
        clock = [0.0]

        def read_code(_kind: str, timeout: float) -> str:
            self.assertEqual(timeout, 300.0)
            clock[0] = 250.0
            return "654321"

        self.run_with(
            account=account,
            cache=_Cache(None),
            auth=auth,
            client=_Client(),
            code_reader=read_code,
            monotonic=lambda: clock[0],
        )
        self.assertEqual(auth.inputs[0][3:], ("654321", 50.0))

    def test_totp_and_workflow_mfa_have_no_discord_input_path(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "totp")
        session = RobinhoodBearerSession("Bearer", "access", 4600.0)
        auth = _Auth(session)
        with self.assertRaisesRegex(RobinhoodRunError, "sensitive details suppressed"):
            self.run_with(account=account, cache=_Cache(None), auth=auth, client=_Client(), bot=object())
        self.assertEqual(auth.authenticated, 0)

    def test_profile_failure_is_redacted_and_invalidates_cache(self) -> None:
        secret_user = "never-log-user"
        secret_token = "never-log-token"
        account = RobinhoodAccount("primary", secret_user, "workflow")
        session = RobinhoodBearerSession("Bearer", secret_token, 4600.0)
        cache = _Cache(session)
        auth = _Auth(session)
        output = io.StringIO()
        with self.assertRaises(RobinhoodRunError), redirect_stdout(output):
            self.run_with(account=account, cache=cache, auth=auth, client=_Client(profile={"error": secret_user}))
        self.assertEqual(cache.removed, 1)
        self.assertNotIn(secret_user, output.getvalue())
        self.assertNotIn(secret_token, output.getvalue())

    def test_malformed_order_response_fails_closed(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "workflow")
        session = RobinhoodBearerSession("Bearer", "access", 4600.0)
        client = _Client(order_response={"detail": "broker failure"})
        with self.assertRaises(RobinhoodRunError):
            self.run_with(account=account, cache=_Cache(session), auth=_Auth(session), client=client, order=_Order(dry=False))
        self.assertEqual(client.order_calls, 1)

    def test_holdings_request_failure_is_not_reported_as_empty_success(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "workflow")
        session = RobinhoodBearerSession("Bearer", "access", 4600.0)
        client = _Client()
        client.positions_response = None
        with self.assertRaises(RobinhoodRunError):
            self.run_with(account=account, cache=_Cache(session), auth=_Auth(session), client=client, order=_Order(holdings=True))

    def test_expired_session_stops_before_live_order(self) -> None:
        account = RobinhoodAccount("primary", "private-user", "workflow")
        session = RobinhoodBearerSession("Bearer", "access", 999.0)
        cache = _Cache(session)
        auth = _Auth(session)
        client = _Client()
        with self.assertRaises(RobinhoodRunError):
            self.run_with(account=account, cache=cache, auth=auth, client=client, order=_Order(dry=False), now=1000.0)
        self.assertEqual(client.order_calls, 0)
        self.assertGreaterEqual(cache.removed, 1)


if __name__ == "__main__":
    unittest.main()
