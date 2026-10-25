"""Bounded local-only Robinhood multi-factor input."""

# Terminal restoration and fixed redacted exception messages are security behavior.
# ruff: file-ignore[ complex-structure, raw-string-in-exception, raise-vanilla-args]

from __future__ import annotations

import os
import select
import sys
import termios
import time
import tty
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import Callable

ROBINHOOD_MFA_TIMEOUT_SECONDS = 300.0
MAX_MFA_CODE_LENGTH = 32


class RobinhoodMFAError(RuntimeError):
    """A fixed-message Robinhood MFA failure."""


class RobinhoodMFACancelledError(RobinhoodMFAError):
    """The operator cancelled Robinhood authentication."""

    def __init__(self) -> None:
        """Create a fixed redacted cancellation error."""
        super().__init__("Robinhood authentication cancelled")


class RobinhoodMFATimedOutError(RobinhoodMFAError):
    """Robinhood MFA exceeded its deadline."""

    def __init__(self) -> None:
        """Create a fixed redacted timeout error."""
        super().__init__("Robinhood authentication timed out")


class RobinhoodMFATerminalError(RobinhoodMFAError):
    """No safe local terminal is available."""

    def __init__(self) -> None:
        """Create a fixed redacted terminal error."""
        super().__init__("Robinhood authentication requires an interactive local terminal")


class RobinhoodMFAUnavailableError(RobinhoodMFAError):
    """MFA was requested through a disallowed channel."""

    def __init__(self) -> None:
        """Create a fixed redacted channel error."""
        super().__init__("Robinhood authentication is unavailable through Discord")


def _open_local_terminal() -> TextIO:
    # A read/write TextIOWrapper requires seek synchronization and fails on
    # Linux SSH pseudo-terminals. MFA only reads here; prompts use stderr.
    return Path("/dev/tty").open("r", encoding="utf-8", buffering=1)


def _read_masked_line(stream: TextIO, output: TextIO, timeout: float) -> str:
    descriptor = stream.fileno()
    if not stream.isatty():
        raise RobinhoodMFATerminalError
    previous = termios.tcgetattr(descriptor)
    characters: list[str] = []
    deadline = time.monotonic() + timeout
    try:
        tty.setcbreak(descriptor)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise RobinhoodMFATimedOutError
            value = os.read(descriptor, 1)
            if not value:
                raise RobinhoodMFATerminalError
            if value in {b"\r", b"\n"}:
                return "".join(characters)
            if value == b"\x03":
                raise RobinhoodMFACancelledError
            if value in {b"\x7f", b"\x08"}:
                if characters:
                    characters.pop()
                    output.write("\b \b")
                    output.flush()
                continue
            try:
                character = value.decode("ascii")
            except UnicodeDecodeError:
                continue
            if character.isprintable() and len(characters) < MAX_MFA_CODE_LENGTH:
                characters.append(character)
                output.write("*")
                output.flush()
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)
        output.write("\n")
        output.flush()


def collect_robinhood_mfa_code(
    challenge_type: str,
    timeout: float,
    *,
    terminal_factory: Callable[[], TextIO] | None = None,
    output: TextIO | None = None,
) -> str:
    """Collect one bounded code from a local terminal without echoing it."""
    if timeout <= 0:
        raise RobinhoodMFATimedOutError
    if challenge_type not in {"totp", "email", "sms"}:
        raise RobinhoodMFAError("Unsupported Robinhood verification challenge")
    terminal_factory = terminal_factory or _open_local_terminal
    output = output or sys.stderr
    try:
        terminal = terminal_factory()
    except OSError as exc:
        raise RobinhoodMFATerminalError from exc
    with terminal:
        output.write(f"Enter the Robinhood {challenge_type} code (or type cancel): ")
        output.flush()
        code = _read_masked_line(terminal, output, timeout).strip()
    if code.casefold() == "cancel":
        raise RobinhoodMFACancelledError
    if not code or len(code) > MAX_MFA_CODE_LENGTH or not code.isascii() or not code.isalnum():
        raise RobinhoodMFAError("Invalid Robinhood verification code")
    return code
