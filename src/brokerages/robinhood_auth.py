"""Fail-closed Robinhood authentication with bounded verification workflows."""

# Authentication deliberately uses fixed redacted errors and explicit fail-closed branches.
# ruff: file-ignore[ complex-structure, raw-string-in-exception, too-many-branches, too-many-statements, no-self-use, if-else-block-instead-of-if-exp, raise-vanilla-args, try-consider-else]

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests
from robin_stocks.robinhood import authentication as robinhood_authentication
from robin_stocks.robinhood import helper as robinhood_helper
from robin_stocks.robinhood.urls import login_url

from src.brokerages.robinhood_mfa import RobinhoodMFATimedOutError
from src.brokerages.robinhood_session import RobinhoodBearerSession, is_valid_bearer_session

if TYPE_CHECKING:
    from collections.abc import Callable

LOGIN_CLIENT_ID = "c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS"
VERIFICATION_TIMEOUT_SECONDS = 300.0
VERIFICATION_POLL_SECONDS = 5.0
MAX_CODE_ATTEMPTS = 3
MAX_REQUEST_FAILURES = 3
TERMINAL_STATUSES = {"denied", "expired", "failed", "rejected"}


class RobinhoodAuthenticationError(RuntimeError):
    """A fixed-message Robinhood authentication failure."""


@dataclass(frozen=True)
class RobinhoodAuthCallbacks:
    """Local-only callbacks used by a verification workflow."""

    read_code: Callable[[str, float], str]
    notify_app: Callable[[], None]


class RobinhoodTransport:
    """Small HTTP boundary around the dependency's configured session."""

    def post(self, url: str, payload: dict[str, Any], *, json_body: bool, timeout: float) -> dict[str, Any]:
        """POST without the dependency's exception-printing helper."""
        try:
            if json_body:
                response = robinhood_helper.SESSION.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=timeout)
            else:
                response = robinhood_helper.SESSION.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                    timeout=timeout,
                )
            data = response.json()
        except (requests.RequestException, ValueError):
            raise RobinhoodAuthenticationError("Robinhood authentication request failed") from None
        if not isinstance(data, dict):
            raise RobinhoodAuthenticationError("Robinhood authentication response was invalid")
        return data

    def get(self, url: str, *, timeout: float) -> dict[str, Any]:
        """GET without the dependency's exception-printing helper."""
        try:
            response = robinhood_helper.SESSION.get(url, timeout=timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError):
            raise RobinhoodAuthenticationError("Robinhood verification request failed") from None
        if not isinstance(data, dict):
            raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
        return data


class RobinhoodAuthenticator:
    """Authenticate and activate bearer state without persistent dependency tokens."""

    def __init__(
        self,
        *,
        transport: RobinhoodTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        device_token_factory: Callable[[], str] = robinhood_authentication.generate_device_token,
    ) -> None:
        """Configure injectable HTTP and timing boundaries."""
        self.transport = transport or RobinhoodTransport()
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.sleep = sleep
        self.device_token_factory = device_token_factory

    @staticmethod
    def clear() -> None:
        """Clear all in-process Robinhood authorization state."""
        robinhood_helper.set_login_state(False)
        robinhood_helper.SESSION.headers.pop("Authorization", None)
        robinhood_helper.SESSION.cookies.clear()

    @staticmethod
    def activate(session: RobinhoodBearerSession) -> None:
        """Activate validated cached bearer state."""
        if not is_valid_bearer_session(session):
            raise RobinhoodAuthenticationError("Robinhood session state was invalid")
        RobinhoodAuthenticator.clear()
        robinhood_helper.update_session("Authorization", f"{session.token_type} {session.access_token}")
        robinhood_helper.set_login_state(True)

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        ttl: int,
        callbacks: RobinhoodAuthCallbacks,
        mfa_code: str | None = None,
        verification_timeout: float = VERIFICATION_TIMEOUT_SECONDS,
    ) -> RobinhoodBearerSession:
        """Perform one password login and return only bounded bearer state."""
        self.clear()
        payload: dict[str, Any] = {
            "client_id": LOGIN_CLIENT_ID,
            "expires_in": ttl,
            "grant_type": "password",
            "password": password,
            "scope": "internal",
            "username": username,
            "device_token": self.device_token_factory(),
            "try_passkeys": False,
            "token_request_path": "/login",
            "create_read_only_secondary_token": True,
        }
        if mfa_code is not None:
            payload["mfa_code"] = mfa_code
        if verification_timeout <= 0 or verification_timeout > VERIFICATION_TIMEOUT_SECONDS:
            raise RobinhoodMFATimedOutError
        deadline = self.monotonic() + verification_timeout
        try:
            data = self.transport.post(login_url(), payload, json_body=False, timeout=self._request_timeout(deadline))
            workflow = data.get("verification_workflow")
            if workflow is not None:
                if not isinstance(workflow, dict) or not isinstance(workflow.get("id"), str):
                    raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
                self._verify_workflow(str(payload["device_token"]), workflow["id"], callbacks, deadline)
                data = self.transport.post(login_url(), payload, json_body=False, timeout=self._request_timeout(deadline))
            token_type = data.get("token_type")
            access_token = data.get("access_token")
            server_ttl = data.get("expires_in", ttl)
            if not isinstance(token_type, str) or not isinstance(access_token, str):
                raise RobinhoodAuthenticationError("Robinhood login was not accepted")
            if isinstance(server_ttl, bool) or not isinstance(server_ttl, int | float) or server_ttl <= 0:
                raise RobinhoodAuthenticationError("Robinhood login response was invalid")
            session = RobinhoodBearerSession(token_type, access_token, self.wall_clock() + min(ttl, float(server_ttl)))
            if not is_valid_bearer_session(session):
                raise RobinhoodAuthenticationError("Robinhood login response was invalid")
            self.activate(session)
            return session
        except Exception:
            self.clear()
            raise

    def _request_timeout(self, deadline: float) -> float:
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise RobinhoodMFATimedOutError
        return min(16.0, remaining)

    def _wait(self, deadline: float) -> None:
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise RobinhoodMFATimedOutError
        self.sleep(min(VERIFICATION_POLL_SECONDS, remaining))

    @staticmethod
    def _challenge(response: dict[str, Any]) -> dict[str, Any] | None:
        context = response.get("context")
        if context is None:
            return None
        if not isinstance(context, dict):
            raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
        challenge = context.get("sheriff_challenge")
        if challenge is None:
            return None
        if not isinstance(challenge, dict):
            raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
        return challenge

    def _verify_workflow(self, device_token: str, workflow_id: str, callbacks: RobinhoodAuthCallbacks, deadline: float) -> None:
        machine = self.transport.post(
            "https://api.robinhood.com/pathfinder/user_machine/",
            {"device_id": device_token, "flow": "suv", "input": {"workflow_id": workflow_id}},
            json_body=True,
            timeout=self._request_timeout(deadline),
        )
        machine_id = machine.get("id")
        if not isinstance(machine_id, str) or not machine_id:
            raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
        inquiry_url = f"https://api.robinhood.com/pathfinder/inquiries/{machine_id}/user_view/"
        code_attempts = 0
        request_failures = 0
        challenge_complete = False
        while not challenge_complete:
            self._wait(deadline)
            try:
                inquiry = self.transport.get(inquiry_url, timeout=self._request_timeout(deadline))
                request_failures = 0
            except RobinhoodAuthenticationError:
                request_failures += 1
                if request_failures >= MAX_REQUEST_FAILURES:
                    raise
                continue
            challenge = self._challenge(inquiry)
            if challenge is None:
                continue
            challenge_type = challenge.get("type")
            status = challenge.get("status")
            challenge_id = challenge.get("id")
            if not isinstance(challenge_type, str) or not isinstance(status, str) or not isinstance(challenge_id, str):
                raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
            if status == "validated":
                challenge_complete = True
                continue
            if status in TERMINAL_STATUSES:
                raise RobinhoodAuthenticationError("Robinhood verification was rejected")
            if challenge_type == "prompt" and status in {"issued", "pending"}:
                callbacks.notify_app()
                self._wait_for_app(challenge_id, deadline)
                challenge_complete = True
                continue
            if challenge_type in {"email", "sms"} and status == "issued":
                if code_attempts >= MAX_CODE_ATTEMPTS:
                    raise RobinhoodAuthenticationError("Robinhood verification attempt limit reached")
                code = callbacks.read_code(challenge_type, deadline - self.monotonic())
                code_attempts += 1
                response = self.transport.post(
                    f"https://api.robinhood.com/challenge/{challenge_id}/respond/",
                    {"response": code},
                    json_body=False,
                    timeout=self._request_timeout(deadline),
                )
                response_status = response.get("status")
                if response_status == "validated":
                    challenge_complete = True
                elif response_status in TERMINAL_STATUSES and code_attempts >= MAX_CODE_ATTEMPTS:
                    raise RobinhoodAuthenticationError("Robinhood verification attempt limit reached")
                elif response_status not in TERMINAL_STATUSES | {"issued", "pending"}:
                    raise RobinhoodAuthenticationError("Robinhood verification response was invalid")
                continue
            raise RobinhoodAuthenticationError("Unsupported Robinhood verification challenge")
        self._confirm_workflow(inquiry_url, deadline)

    def _wait_for_app(self, challenge_id: str, deadline: float) -> None:
        prompt_url = f"https://api.robinhood.com/push/{challenge_id}/get_prompts_status/"
        failures = 0
        while True:
            self._wait(deadline)
            try:
                response = self.transport.get(prompt_url, timeout=self._request_timeout(deadline))
                failures = 0
            except RobinhoodAuthenticationError:
                failures += 1
                if failures >= MAX_REQUEST_FAILURES:
                    raise
                continue
            status = response.get("challenge_status")
            if status == "validated":
                return
            if status in TERMINAL_STATUSES:
                raise RobinhoodAuthenticationError("Robinhood verification was rejected")
            if status not in {"issued", "pending"}:
                raise RobinhoodAuthenticationError("Robinhood verification response was invalid")

    def _confirm_workflow(self, inquiry_url: str, deadline: float) -> None:
        failures = 0
        while True:
            response = self.transport.post(
                inquiry_url,
                {"sequence": 0, "user_input": {"status": "continue"}},
                json_body=True,
                timeout=self._request_timeout(deadline),
            )
            type_context = response.get("type_context")
            if isinstance(type_context, dict) and type_context.get("result") == "workflow_status_approved":
                return
            status = response.get("verification_workflow")
            workflow_status = status.get("workflow_status") if isinstance(status, dict) else None
            if workflow_status == "workflow_status_approved":
                return
            if workflow_status in {"workflow_status_internal_pending", None}:
                failures += 1
                if failures >= MAX_REQUEST_FAILURES:
                    raise RobinhoodAuthenticationError("Robinhood verification did not complete")
                self._wait(deadline)
                continue
            raise RobinhoodAuthenticationError("Robinhood verification was rejected")
