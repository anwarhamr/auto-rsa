from __future__ import annotations

import io
import unittest
from collections import deque
from unittest import mock

from robin_stocks.robinhood import helper as robinhood_helper

from src.brokerages import robinhood_mfa
from src.brokerages.robinhood_auth import (
    MAX_CODE_ATTEMPTS,
    RobinhoodAuthCallbacks,
    RobinhoodAuthenticationError,
    RobinhoodAuthenticator,
)
from src.brokerages.robinhood_mfa import (
    RobinhoodMFACancelledError,
    RobinhoodMFAError,
    RobinhoodMFATimedOutError,
    collect_robinhood_mfa_code,
)


class _Terminal:
    def __enter__(self) -> _Terminal:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def now(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _Transport:
    def __init__(self, posts: list[dict[str, object]], gets: list[dict[str, object]]) -> None:
        self.posts = deque(posts)
        self.gets = deque(gets)
        self.post_calls: list[tuple[str, dict[str, object], bool, float]] = []
        self.get_calls: list[tuple[str, float]] = []

    def post(self, url: str, payload: dict[str, object], *, json_body: bool, timeout: float) -> dict[str, object]:
        self.post_calls.append((url, payload, json_body, timeout))
        if not self.posts:
            raise AssertionError("unexpected POST")
        return self.posts.popleft()

    def get(self, url: str, *, timeout: float) -> dict[str, object]:
        self.get_calls.append((url, timeout))
        if not self.gets:
            raise AssertionError("unexpected GET")
        response = self.gets[0]
        if len(self.gets) > 1:
            return self.gets.popleft()
        return response


def callbacks(codes: list[str] | None = None) -> RobinhoodAuthCallbacks:
    values = deque(codes or [])
    return RobinhoodAuthCallbacks(read_code=lambda _kind, _timeout: values.popleft(), notify_app=lambda: None)


class RobinhoodMFAInputTests(unittest.TestCase):
    def test_code_is_masked_and_never_echoed(self) -> None:
        output = io.StringIO()
        with mock.patch.object(robinhood_mfa, "_read_masked_line", return_value="654321"):
            result = collect_robinhood_mfa_code("sms", 30, terminal_factory=_Terminal, output=output)  # type: ignore[arg-type]
        self.assertEqual(result, "654321")
        self.assertNotIn(result, output.getvalue())

    def test_cancel_timeout_invalid_and_unknown_are_redacted(self) -> None:
        output = io.StringIO()
        with mock.patch.object(robinhood_mfa, "_read_masked_line", return_value="cancel"):
            with self.assertRaises(RobinhoodMFACancelledError):
                collect_robinhood_mfa_code("email", 30, terminal_factory=_Terminal, output=output)  # type: ignore[arg-type]
        with self.assertRaises(RobinhoodMFATimedOutError):
            collect_robinhood_mfa_code("sms", 0)
        with mock.patch.object(robinhood_mfa, "_read_masked_line", return_value="code with spaces"):
            with self.assertRaises(RobinhoodMFAError):
                collect_robinhood_mfa_code("totp", 30, terminal_factory=_Terminal, output=output)  # type: ignore[arg-type]
        with self.assertRaisesRegex(RobinhoodMFAError, "Unsupported"):
            collect_robinhood_mfa_code("push", 30)

    def test_terminal_reader_restores_state_on_timeout(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 7
        stream.isatty.return_value = True
        terminal_state = [object()]
        with (
            mock.patch.object(robinhood_mfa.termios, "tcgetattr", return_value=terminal_state),
            mock.patch.object(robinhood_mfa.tty, "setcbreak"),
            mock.patch.object(robinhood_mfa.select, "select", return_value=([], [], [])),
            mock.patch.object(robinhood_mfa.termios, "tcsetattr") as restore,
        ):
            with self.assertRaises(RobinhoodMFATimedOutError):
                robinhood_mfa._read_masked_line(stream, io.StringIO(), 0.01)
        restore.assert_called_once_with(7, robinhood_mfa.termios.TCSADRAIN, terminal_state)


class RobinhoodAuthenticatorTests(unittest.TestCase):
    def tearDown(self) -> None:
        RobinhoodAuthenticator.clear()

    def make_auth(self, transport: _Transport, clock: _Clock) -> RobinhoodAuthenticator:
        return RobinhoodAuthenticator(
            transport=transport,  # type: ignore[arg-type]
            monotonic=clock.now,
            wall_clock=lambda: 1000.0,
            sleep=clock.sleep,
            device_token_factory=lambda: "ephemeral-device",
        )

    def test_direct_login_requires_and_activates_access_token_only(self) -> None:
        transport = _Transport([{"token_type": "Bearer", "access_token": "access", "refresh_token": "ignored"}], [])
        auth = self.make_auth(transport, _Clock())
        session = auth.authenticate(username="private-user", password="private-password", ttl=3600, callbacks=callbacks())
        self.assertEqual(session.expires_at, 4600.0)
        self.assertEqual(robinhood_helper.SESSION.headers["Authorization"], "Bearer access")
        payload = transport.post_calls[0][1]
        self.assertEqual(payload["expires_in"], 3600)
        self.assertEqual(payload["device_token"], "ephemeral-device")
        self.assertNotIn("private-password", repr(session))

    def test_server_shorter_expiry_is_honored_and_unsafe_bearer_is_rejected(self) -> None:
        auth = self.make_auth(_Transport([{"token_type": "Bearer", "access_token": "access", "expires_in": 600}], []), _Clock())
        session = auth.authenticate(username="user", password="password", ttl=3600, callbacks=callbacks())
        self.assertEqual(session.expires_at, 1600.0)
        unsafe = self.make_auth(_Transport([{"token_type": "Bearer", "access_token": "token\nInjected: value"}], []), _Clock())
        with self.assertRaisesRegex(RobinhoodAuthenticationError, "invalid"):
            unsafe.authenticate(username="user", password="password", ttl=3600, callbacks=callbacks())
        self.assertNotIn("Authorization", robinhood_helper.SESSION.headers)

    def test_missing_access_token_fails_and_clears_prior_authorization(self) -> None:
        robinhood_helper.SESSION.headers["Authorization"] = "Bearer stale"
        auth = self.make_auth(_Transport([{"detail": "bad private-password"}], []), _Clock())
        with self.assertRaisesRegex(RobinhoodAuthenticationError, "not accepted"):
            auth.authenticate(username="private-user", password="private-password", ttl=3600, callbacks=callbacks())
        self.assertNotIn("Authorization", robinhood_helper.SESSION.headers)

    def test_email_workflow_is_bounded_and_then_login_is_retried(self) -> None:
        transport = _Transport(
            [
                {"verification_workflow": {"id": "workflow"}},
                {"id": "machine"},
                {"status": "validated"},
                {"type_context": {"result": "workflow_status_approved"}},
                {"token_type": "Bearer", "access_token": "access"},
            ],
            [{"context": {"sheriff_challenge": {"type": "email", "status": "issued", "id": "challenge"}}}],
        )
        auth = self.make_auth(transport, _Clock())
        session = auth.authenticate(username="user", password="password", ttl=300, callbacks=callbacks(["123456"]))
        self.assertEqual(session.access_token, "access")
        challenge_payloads = [call[1] for call in transport.post_calls if "/challenge/" in call[0]]
        self.assertEqual(challenge_payloads, [{"response": "123456"}])

    def test_email_attempts_stop_at_limit(self) -> None:
        challenge = {"context": {"sheriff_challenge": {"type": "sms", "status": "issued", "id": "challenge"}}}
        transport = _Transport(
            [
                {"verification_workflow": {"id": "workflow"}},
                {"id": "machine"},
                *[{"status": "rejected"} for _ in range(MAX_CODE_ATTEMPTS)],
            ],
            [challenge, challenge, challenge],
        )
        auth = self.make_auth(transport, _Clock())
        with self.assertRaisesRegex(RobinhoodAuthenticationError, "attempt limit"):
            auth.authenticate(username="user", password="password", ttl=300, callbacks=callbacks(["1", "2", "3"]))
        self.assertEqual(len([call for call in transport.post_calls if "/challenge/" in call[0]]), MAX_CODE_ATTEMPTS)

    def test_app_poll_obeys_single_overall_deadline(self) -> None:
        transport = _Transport(
            [{"verification_workflow": {"id": "workflow"}}, {"id": "machine"}],
            [
                {"context": {"sheriff_challenge": {"type": "prompt", "status": "issued", "id": "challenge"}}},
                {"challenge_status": "pending"},
            ],
        )
        clock = _Clock()
        auth = self.make_auth(transport, clock)
        with self.assertRaises(RobinhoodMFATimedOutError):
            auth.authenticate(username="user", password="password", ttl=300, callbacks=callbacks())
        self.assertLessEqual(clock.value, 300.0)
        self.assertNotIn("Authorization", robinhood_helper.SESSION.headers)

    def test_unknown_challenge_fails_closed(self) -> None:
        transport = _Transport(
            [{"verification_workflow": {"id": "workflow"}}, {"id": "machine"}],
            [{"context": {"sheriff_challenge": {"type": "voice", "status": "issued", "id": "challenge"}}}],
        )
        auth = self.make_auth(transport, _Clock())
        with self.assertRaisesRegex(RobinhoodAuthenticationError, "Unsupported"):
            auth.authenticate(username="user", password="password", ttl=300, callbacks=callbacks())


if __name__ == "__main__":
    unittest.main()
