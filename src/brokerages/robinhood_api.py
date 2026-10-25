"""Hardened Robinhood brokerage execution."""

# Broker response validation uses fixed redacted failures and explicit checks.
# ruff: file-ignore[ complex-structure, raw-string-in-exception, too-many-locals, too-many-statements, too-many-boolean-expressions, if-else-block-instead-of-if-exp, raise-vanilla-args]

from __future__ import annotations

import contextlib
import os
import time
from typing import TYPE_CHECKING, Any, cast

from dotenv import load_dotenv
from robin_stocks import robinhood as rh

from src.brokerages.robinhood_auth import VERIFICATION_TIMEOUT_SECONDS, RobinhoodAuthCallbacks, RobinhoodAuthenticator
from src.brokerages.robinhood_credentials import (
    RobinhoodAccount,
    load_robinhood_accounts,
    load_robinhood_passwords,
    load_session_ttl,
)
from src.brokerages.robinhood_mfa import RobinhoodMFAUnavailableError, collect_robinhood_mfa_code
from src.brokerages.robinhood_session import RobinhoodBearerSession, RobinhoodSessionCache
from src.helper_api import Brokerage, StockOrder, mask_string, print_all_holdings, print_and_discord

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Callable, Mapping

    from discord.ext.commands import Bot


class RobinhoodRunError(RuntimeError):
    """A redacted Robinhood run failure."""


class RobinhoodClient:
    """Testable boundary around account and trading calls from robin_stocks."""

    @staticmethod
    def account_profile() -> object:
        """Load all accounts for the active identity."""
        return rh.account.load_account_profile(dataType="results")

    @staticmethod
    def positions(account_number: str) -> object:
        """Load positions for one account."""
        return rh.get_open_stock_positions(account_number=account_number)

    @staticmethod
    def symbol(instrument_url: str) -> object:
        """Resolve an instrument URL to its symbol."""
        return rh.get_symbol_by_url(instrument_url)

    @staticmethod
    def latest_price(symbol: str, price_type: str | None = None) -> object:
        """Load a current or typed price."""
        if price_type is None:
            return rh.stocks.get_latest_price(symbol)
        return rh.get_latest_price(symbol, priceType=price_type)

    @staticmethod
    def order(**kwargs: object) -> object:
        """Submit one order through the active identity."""
        return rh.order(**kwargs)


def _validated_profile(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RobinhoodRunError("Robinhood account profile validation failed")
    accounts: list[dict[str, Any]] = []
    required = {"account_number", "portfolio_cash", "brokerage_account_type"}
    for item in value:
        if not isinstance(item, dict) or not required.issubset(item):
            raise RobinhoodRunError("Robinhood account profile validation failed")
        if not all(isinstance(item[key], str) and item[key] for key in required):
            raise RobinhoodRunError("Robinhood account profile validation failed")
        accounts.append(item)
    return accounts


def _populate_accounts(rho: Brokerage, name: str, profile: list[dict[str, Any]], known_numbers: set[str]) -> list[str]:
    numbers: list[str] = []
    for item in profile:
        account_number = cast("str", item["account_number"])
        if account_number in known_numbers:
            raise RobinhoodRunError("Duplicate Robinhood account number")
        known_numbers.add(account_number)
        numbers.append(account_number)
        rho.set_account_number(name, account_number)
        try:
            rho.set_account_totals(name, account_number, cast("str", item["portfolio_cash"]))
        except (TypeError, ValueError):
            raise RobinhoodRunError("Robinhood account profile validation failed") from None
        rho.set_account_type(name, account_number, cast("str", item["brokerage_account_type"]))
        print(f"Found {item['brokerage_account_type']} account {mask_string(account_number)}")
    return numbers


def _holdings_for_accounts(
    client: RobinhoodClient,
    rho: Brokerage,
    name: str,
    accounts: list[str],
    ensure_active: Callable[[], None],
) -> None:
    for account in accounts:
        ensure_active()
        positions = client.positions(account)
        if not isinstance(positions, list):
            raise RobinhoodRunError("Robinhood holdings response was invalid")
        for item in positions:
            if not isinstance(item, dict) or not isinstance(item.get("instrument"), str) or not isinstance(item.get("quantity"), str):
                raise RobinhoodRunError("Robinhood holdings response was invalid")
            symbol = client.symbol(item["instrument"])
            if not isinstance(symbol, str) or not symbol:
                raise RobinhoodRunError("Robinhood holdings response was invalid")
            try:
                quantity = float(item["quantity"])
            except ValueError:
                raise RobinhoodRunError("Robinhood holdings response was invalid") from None
            current_price: float | str = "N/A"
            ensure_active()
            with contextlib.suppress(Exception):
                prices = client.latest_price(symbol)
                if isinstance(prices, list) and prices and prices[0] is not None:
                    current_price = round(float(prices[0]), 2)
            rho.set_holdings(name, account, symbol, quantity, current_price)


def _order_message(response: object) -> str:
    if not isinstance(response, dict) or response.get("non_field_errors") is not None or response.get("detail") is not None:
        raise RobinhoodRunError("Robinhood order was rejected")
    order_id = response.get("id")
    if not isinstance(order_id, str) or not order_id:
        raise RobinhoodRunError("Robinhood order response was invalid")
    return "Success"


def _transactions_for_accounts(
    client: RobinhoodClient,
    accounts: list[str],
    name: str,
    order_obj: StockOrder,
    loop: asyncio.AbstractEventLoop | None,
    *,
    ensure_active: Callable[[], None],
) -> None:
    for symbol in order_obj.get_stocks():
        print_and_discord(f"{name}: {order_obj.get_action()}ing {order_obj.get_amount()} of {symbol}", loop)
        for account in accounts:
            ensure_active()
            print_account = mask_string(account)
            if order_obj.get_dry():
                print_and_discord(
                    f"{name} {print_account} Running in DRY mode. Transaction would've been: {order_obj.get_action()} {order_obj.get_amount()} of {symbol}",
                    loop,
                )
                continue
            market_order = client.order(
                symbol=symbol,
                quantity=order_obj.get_amount(),
                side=order_obj.get_action(),
                account_number=account,
                timeInForce="gfd",
            )
            if market_order is not None:
                print_and_discord(
                    f"{name}: {order_obj.get_action()} {order_obj.get_amount()} of {symbol} in {print_account}: {_order_message(market_order)}",
                    loop,
                )
                continue
            print_and_discord(
                f"{name}: Market order was not accepted in {print_account}; trying limit order",
                loop,
            )
            ensure_active()
            asks = client.latest_price(symbol, "ask_price")
            bids = client.latest_price(symbol, "bid_price")
            if not isinstance(asks, list) or not asks or asks[0] is None or not isinstance(bids, list) or not bids or bids[0] is None:
                raise RobinhoodRunError("Robinhood quote response was invalid")
            try:
                if order_obj.get_action() == "buy":
                    price = round(max(float(bids[0]), float(asks[0])) + 0.01, 2)
                else:
                    price = round(min(float(bids[0]), float(asks[0])) - 0.01, 2)
            except (TypeError, ValueError):
                raise RobinhoodRunError("Robinhood quote response was invalid") from None
            ensure_active()
            limit_order = client.order(
                symbol=symbol,
                quantity=order_obj.get_amount(),
                side=order_obj.get_action(),
                limitPrice=price,
                account_number=account,
                timeInForce="gfd",
            )
            if limit_order is None:
                raise RobinhoodRunError("Robinhood order was rejected")
            print_and_discord(
                f"{name}: {order_obj.get_action()} {order_obj.get_amount()} of {symbol} in {print_account} @ {price}: {_order_message(limit_order)}",
                loop,
            )


def _callbacks(*, interactive_allowed: bool, code_reader: Callable[[str, float], str]) -> RobinhoodAuthCallbacks:
    def read_code(challenge_type: str, timeout: float) -> str:
        if not interactive_allowed:
            raise RobinhoodMFAUnavailableError
        return code_reader(challenge_type, timeout)

    def notify_app() -> None:
        if not interactive_allowed:
            raise RobinhoodMFAUnavailableError
        print("Approve the Robinhood sign-in in the local operator's Robinhood app.")

    return RobinhoodAuthCallbacks(read_code=read_code, notify_app=notify_app)


def _load_sessions(
    accounts: tuple[RobinhoodAccount, ...],
    cache: RobinhoodSessionCache,
) -> tuple[dict[str, RobinhoodBearerSession], set[str]]:
    sessions: dict[str, RobinhoodBearerSession] = {}
    missing: set[str] = set()
    for account in accounts:
        session = cache.load(account.name, account.username)
        if session is None:
            missing.add(account.name)
        else:
            sessions[account.name] = session
    return sessions, missing


def robinhood_run(
    order_obj: StockOrder,
    bot_obj: Bot | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    authenticator: RobinhoodAuthenticator | None = None,
    client: RobinhoodClient | None = None,
    code_reader: Callable[[str, float], str] = collect_robinhood_mfa_code,
    wall_clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Authenticate each Robinhood identity once, execute, and clear process state."""
    if bot_obj is not None or loop is not None:
        raise RobinhoodRunError("Robinhood operations are unavailable through Discord")
    load_dotenv()
    environment = os.environ if environ is None else environ
    accounts = load_robinhood_accounts(environment)
    if accounts is None:
        print("Robinhood not found, skipping...")
        return
    ttl = load_session_ttl(environment)
    cache = RobinhoodSessionCache.from_environment(environment, wall_clock=wall_clock)
    sessions, missing = _load_sessions(accounts, cache)
    passwords = load_robinhood_passwords(missing, environment)
    auth = authenticator or RobinhoodAuthenticator(wall_clock=wall_clock)
    api = client or RobinhoodClient()
    callbacks = _callbacks(interactive_allowed=bot_obj is None and loop is None, code_reader=code_reader)
    rho = Brokerage("Robinhood")
    known_numbers: set[str] = set()
    try:
        for index, account in enumerate(accounts, start=1):
            name = f"Robinhood {index}"
            print(f"Logging in to {name}...")
            session = sessions.get(account.name)
            try:
                if session is None:
                    verification_deadline = monotonic() + VERIFICATION_TIMEOUT_SECONDS
                    mfa_code = callbacks.read_code("totp", verification_deadline - monotonic()) if account.mfa == "totp" else None
                    remaining = verification_deadline - monotonic()
                    session = auth.authenticate(
                        username=account.username,
                        password=passwords[account.name].password,
                        ttl=ttl,
                        callbacks=callbacks,
                        mfa_code=mfa_code,
                        verification_timeout=remaining,
                    )
                    cache.save(account.name, account.username, session)
                else:
                    auth.activate(session)
                profile = _validated_profile(api.account_profile())
                account_numbers = _populate_accounts(rho, name, profile, known_numbers)

                active_session = session

                def ensure_active(active_session: RobinhoodBearerSession = active_session) -> None:
                    if wall_clock() >= active_session.expires_at:
                        raise RobinhoodRunError("Robinhood session expired")

                ensure_active()
                if order_obj.get_holdings():
                    _holdings_for_accounts(api, rho, name, account_numbers, ensure_active)
                else:
                    _transactions_for_accounts(api, account_numbers, name, order_obj, loop, ensure_active=ensure_active)
                print(f"Logged in to {name}")
            except Exception:
                if session is not None:
                    cache.remove(account.name, account.username)
                raise
            finally:
                auth.clear()
    except Exception:
        auth.clear()
        print("Robinhood operation failed; sensitive details suppressed")
        raise RobinhoodRunError("Robinhood operation failed; sensitive details suppressed") from None
    if order_obj.get_holdings():
        print_all_holdings(rho, loop)
