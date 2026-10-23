"""Local-only, redaction-safe Chase multi-factor input."""

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

CHASE_MFA_CODE_LENGTH = 8
CHASE_MFA_TIMEOUT_SECONDS = 300.0


class ChaseMFAError(RuntimeError):
    """A redacted Chase multi-factor input failure."""


class ChaseMFACancelledError(ChaseMFAError):
    """The operator explicitly cancelled Chase authentication."""

    def __init__(self) -> None:
        """Create a cancellation error with a fixed redacted message."""
        super().__init__("Chase authentication cancelled")


class ChaseMFATimedOutError(ChaseMFAError):
    """The local Chase multi-factor prompt timed out."""

    def __init__(self) -> None:
        """Create a timeout error with a fixed redacted message."""
        super().__init__("Chase authentication timed out")


class ChaseMFATerminalError(ChaseMFAError):
    """No safe local terminal is available for Chase authentication."""

    def __init__(self) -> None:
        """Create a terminal error with a fixed redacted message."""
        super().__init__("Chase authentication requires an interactive local terminal")


class ChaseMFAUnavailableError(ChaseMFAError):
    """Chase MFA was requested in a channel that cannot safely collect it."""

    def __init__(self) -> None:
        """Create a channel error with a fixed redacted message."""
        super().__init__("Chase authentication is unavailable through Discord")


def _open_local_terminal() -> TextIO:
    return Path("/dev/tty").open("r+", encoding="utf-8", buffering=1)


def _read_available_byte(descriptor: int, remaining: float) -> bytes:
    if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
        raise ChaseMFATimedOutError
    value = os.read(descriptor, 1)
    if not value:
        raise ChaseMFATerminalError
    return value


def _read_masked_line(stream: TextIO, output: TextIO, timeout: float) -> str:
    """Read one terminal line with echo disabled and asterisks displayed."""
    descriptor = stream.fileno()
    if not stream.isatty():
        raise ChaseMFATerminalError

    previous = termios.tcgetattr(descriptor)
    characters: list[str] = []
    deadline = time.monotonic() + timeout
    try:
        tty.setcbreak(descriptor)
        while True:
            remaining = deadline - time.monotonic()
            value = _read_available_byte(descriptor, remaining)
            if value in {b"\r", b"\n"}:
                return "".join(characters)
            if value == b"\x03":
                raise ChaseMFACancelledError
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
            if character.isprintable():
                characters.append(character)
                output.write("*")
                output.flush()
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)
        output.write("\n")
        output.flush()


def collect_chase_mfa_code(
    *,
    timeout: float = CHASE_MFA_TIMEOUT_SECONDS,
    terminal_factory: Callable[[], TextIO] | None = None,
    output: TextIO | None = None,
) -> str:
    """Collect and validate an 8-digit Chase code from the local terminal only."""
    if timeout <= 0:
        raise ChaseMFATimedOutError

    output = output or sys.stderr
    terminal_factory = terminal_factory or _open_local_terminal
    deadline = time.monotonic() + timeout
    try:
        terminal = terminal_factory()
    except OSError as exc:
        raise ChaseMFATerminalError from exc

    with terminal:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChaseMFATimedOutError
            output.write("Enter the 8-digit Chase code (or type cancel): ")
            output.flush()
            code = _read_masked_line(terminal, output, remaining)
            if code.casefold() == "cancel":
                raise ChaseMFACancelledError
            if len(code) == CHASE_MFA_CODE_LENGTH and code.isascii() and code.isdecimal():
                return code
            output.write("Invalid Chase code; enter exactly 8 digits or type cancel.\n")
            output.flush()
