"""Protected Robinhood account configuration and one-time password input."""

# Security validation intentionally uses fixed redacted messages and independent checks.
# ruff: file-ignore[ complex-structure, raw-string-in-exception, f-string-in-exception, compare-to-empty-string, magic-value-comparison, hardcoded-password-string, suppressible-exception, raise-vanilla-args]

from __future__ import annotations

import json
import os
import re
import select
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

ACCOUNTS_FILE_ENV = "RSA_ROBINHOOD_ACCOUNTS_FILE"
PASSWORD_FILE_ENV = "RSA_ROBINHOOD_PASSWORD_FILE"
SESSION_DIR_ENV = "RSA_ROBINHOOD_SESSION_DIR"
SESSION_TTL_ENV = "RSA_ROBINHOOD_SESSION_TTL_SECONDS"
LEGACY_CREDENTIALS_ENV = "ROBINHOOD"
DEFAULT_SESSION_TTL_SECONDS = 3600
MIN_SESSION_TTL_SECONDS = 300
MAX_SESSION_TTL_SECONDS = 86400
MAX_INPUT_BYTES = 64 * 1024
PASSWORD_INPUT_TIMEOUT_SECONDS = 60.0
_MOUNT_POINT_INDEX = 4
_ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class RobinhoodCredentialError(RuntimeError):
    """Report a Robinhood configuration failure without exposing submitted values."""


@dataclass(frozen=True, repr=False)
class RobinhoodAccount:
    """One protected durable Robinhood username configuration."""

    name: str
    username: str = field(repr=False)
    mfa: str

    def __repr__(self) -> str:
        """Never render the username."""
        return f"RobinhoodAccount(name={self.name!r}, username=<redacted>, mfa={self.mfa!r})"


@dataclass(frozen=True, repr=False)
class RobinhoodPassword:
    """One consumed Robinhood password."""

    name: str
    password: str = field(repr=False)

    def __repr__(self) -> str:
        """Never render the password."""
        return f"RobinhoodPassword(name={self.name!r}, password=<redacted>)"


class _DuplicateJsonKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


def _decode_document(payload: bytes, description: str) -> dict[str, object]:
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError):
        raise RobinhoodCredentialError(f"Invalid Robinhood {description} JSON") from None
    if not isinstance(document, dict):
        raise RobinhoodCredentialError(f"Invalid Robinhood {description} document")
    return document


def _require_exact_keys(value: Mapping[str, object], expected: set[str], description: str) -> None:
    if set(value) != expected:
        raise RobinhoodCredentialError(f"Invalid Robinhood {description} fields")


def _validate_document_header(document: Mapping[str, object], description: str) -> list[object]:
    _require_exact_keys(document, {"version", "broker", description}, f"{description} document")
    if type(document["version"]) is not int or document["version"] != 1:
        raise RobinhoodCredentialError("Unsupported Robinhood configuration schema version")
    if document["broker"] != "robinhood":
        raise RobinhoodCredentialError("Robinhood configuration broker must be 'robinhood'")
    values = document[description]
    if not isinstance(values, list) or not values:
        raise RobinhoodCredentialError(f"Robinhood {description} must be a non-empty list")
    return values


def parse_robinhood_accounts(payload: bytes) -> tuple[RobinhoodAccount, ...]:
    """Parse versioned durable Robinhood account configuration."""
    document = _decode_document(payload, "account")
    values = _validate_document_header(document, "accounts")
    accounts: list[RobinhoodAccount] = []
    names: set[str] = set()
    usernames: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise RobinhoodCredentialError("Invalid Robinhood account entry")
        _require_exact_keys(value, {"name", "username", "mfa"}, "account")
        name = value["name"]
        username = value["username"]
        mfa = value["mfa"]
        if not isinstance(name, str) or _ACCOUNT_NAME.fullmatch(name) is None:
            raise RobinhoodCredentialError("Invalid Robinhood account name")
        if not isinstance(username, str) or not username or len(username) > 320 or any(character in username for character in "\r\n\x00"):
            raise RobinhoodCredentialError("Invalid Robinhood username")
        if mfa not in {"workflow", "totp"}:
            raise RobinhoodCredentialError("Invalid Robinhood MFA mode")
        normalized_username = username.casefold()
        if name in names or normalized_username in usernames:
            raise RobinhoodCredentialError("Duplicate Robinhood account configuration")
        names.add(name)
        usernames.add(normalized_username)
        accounts.append(RobinhoodAccount(name, username, str(mfa)))
    return tuple(accounts)


def parse_robinhood_passwords(payload: bytes) -> dict[str, RobinhoodPassword]:
    """Parse a versioned one-time Robinhood password payload."""
    document = _decode_document(payload, "password")
    values = _validate_document_header(document, "passwords")
    passwords: dict[str, RobinhoodPassword] = {}
    for value in values:
        if not isinstance(value, dict):
            raise RobinhoodCredentialError("Invalid Robinhood password entry")
        _require_exact_keys(value, {"name", "password"}, "password")
        name = value["name"]
        password = value["password"]
        if not isinstance(name, str) or _ACCOUNT_NAME.fullmatch(name) is None:
            raise RobinhoodCredentialError("Invalid Robinhood password account name")
        if not isinstance(password, str) or not password or len(password) > 4096 or "\x00" in password:
            raise RobinhoodCredentialError("Invalid Robinhood password")
        if name in passwords:
            raise RobinhoodCredentialError("Duplicate Robinhood password entry")
        passwords[name] = RobinhoodPassword(name, password)
    return passwords


def _decode_mount_path(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def is_tmpfs(path: str) -> bool:
    """Return whether a path is on Linux tmpfs, failing closed elsewhere."""
    target = os.path.realpath(path)
    best_mount = ""
    best_type = ""
    try:
        with Path("/proc/self/mountinfo").open(encoding="utf-8") as mounts:
            for line in mounts:
                left, separator, right = line.partition(" - ")
                if not separator:
                    continue
                fields = left.split()
                filesystem = right.split(maxsplit=1)[0]
                if len(fields) <= _MOUNT_POINT_INDEX:
                    continue
                mount_point = _decode_mount_path(fields[_MOUNT_POINT_INDEX])
                if (target == mount_point or target.startswith(mount_point.rstrip("/") + "/")) and len(mount_point) > len(best_mount):
                    best_mount = mount_point
                    best_type = filesystem
    except OSError:
        return False
    return best_type == "tmpfs"


def _validate_path(path: str, *, description: str, regular_only: bool, require_tmpfs: bool) -> os.stat_result:
    if not Path(path).is_absolute():
        raise RobinhoodCredentialError(f"Robinhood {description} path must be absolute")
    if os.path.realpath(path) != path:
        raise RobinhoodCredentialError(f"Robinhood {description} path must not contain symlinks")
    try:
        path_stat = os.lstat(path)
    except OSError as exc:
        raise RobinhoodCredentialError(f"Unable to open Robinhood {description}") from exc
    accepted_type = stat.S_ISREG(path_stat.st_mode) if regular_only else stat.S_ISREG(path_stat.st_mode) or stat.S_ISFIFO(path_stat.st_mode)
    if not accepted_type:
        raise RobinhoodCredentialError(f"Robinhood {description} has an invalid file type")
    if path_stat.st_mode & 0o077:
        raise RobinhoodCredentialError(f"Robinhood {description} must not grant group or other permissions")
    if hasattr(os, "geteuid") and path_stat.st_uid != os.geteuid():
        raise RobinhoodCredentialError(f"Robinhood {description} must be owned by the current user")
    if require_tmpfs and stat.S_ISREG(path_stat.st_mode) and not is_tmpfs(path):
        raise RobinhoodCredentialError(f"Robinhood {description} must be on tmpfs")
    if stat.S_ISREG(path_stat.st_mode) and path_stat.st_size > MAX_INPUT_BYTES:
        raise RobinhoodCredentialError(f"Robinhood {description} exceeds the size limit")
    return path_stat


def _read_fifo(descriptor: int, timeout: float, path: str, description: str) -> bytes:
    deadline = time.monotonic() + timeout
    payload = bytearray()
    consumed = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RobinhoodCredentialError("Robinhood password input timed out")
        if not select.select([descriptor], [], [], remaining)[0]:
            raise RobinhoodCredentialError("Robinhood password input timed out")
        try:
            chunk = os.read(descriptor, MAX_INPUT_BYTES + 1 - len(payload))
        except BlockingIOError:
            time.sleep(min(0.05, remaining))
            continue
        if chunk:
            if not consumed:
                try:
                    Path(path).unlink()
                except OSError as exc:
                    raise RobinhoodCredentialError(f"Unable to consume Robinhood {description}") from exc
                consumed = True
            payload.extend(chunk)
            if len(payload) > MAX_INPUT_BYTES:
                raise RobinhoodCredentialError("Robinhood password input exceeds the size limit")
            continue
        if payload:
            return bytes(payload)
        time.sleep(min(0.05, remaining))


def _read_protected_file(path: str, *, description: str, consume: bool, require_tmpfs: bool, fifo_timeout: float = PASSWORD_INPUT_TIMEOUT_SECONDS) -> bytes:
    path_stat = _validate_path(path, description=description, regular_only=not consume, require_tmpfs=require_tmpfs)
    is_fifo = stat.S_ISFIFO(path_stat.st_mode)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if is_fifo:
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RobinhoodCredentialError(f"Unable to open Robinhood {description}") from exc
    accepted = False
    try:
        opened_stat = os.fstat(descriptor)
        if (opened_stat.st_dev, opened_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise RobinhoodCredentialError(f"Robinhood {description} changed while opening")
        if opened_stat.st_mode & 0o077 or (hasattr(os, "geteuid") and opened_stat.st_uid != os.geteuid()):
            raise RobinhoodCredentialError(f"Robinhood {description} protection changed while opening")
        if consume and not is_fifo:
            try:
                Path(path).unlink()
            except OSError as exc:
                raise RobinhoodCredentialError(f"Unable to consume Robinhood {description}") from exc
        accepted = True
        if is_fifo:
            payload = _read_fifo(descriptor, fifo_timeout, path, description)
        else:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise RobinhoodCredentialError(f"Robinhood {description} exceeds the size limit")
        return payload
    finally:
        os.close(descriptor)
        if accepted and consume:
            try:
                Path(path).unlink()
            except OSError:
                pass


def load_robinhood_accounts(environ: Mapping[str, str] | None = None) -> tuple[RobinhoodAccount, ...] | None:
    """Load protected Robinhood usernames and reject legacy environment credentials."""
    environment = os.environ if environ is None else environ
    if environment.get(LEGACY_CREDENTIALS_ENV, ""):
        raise RobinhoodCredentialError("Legacy ROBINHOOD credentials are disabled")
    path = environment.get(ACCOUNTS_FILE_ENV, "").strip()
    if not path:
        return None
    return parse_robinhood_accounts(_read_protected_file(path, description="account configuration", consume=False, require_tmpfs=False))


def load_robinhood_passwords(
    required_names: set[str],
    environ: Mapping[str, str] | None = None,
    *,
    fifo_timeout: float = PASSWORD_INPUT_TIMEOUT_SECONDS,
) -> dict[str, RobinhoodPassword]:
    """Consume one-time passwords and require an exact mapping for cache misses."""
    environment = os.environ if environ is None else environ
    path = environment.get(PASSWORD_FILE_ENV, "").strip()
    if not path:
        if not required_names:
            return {}
        raise RobinhoodCredentialError("Robinhood one-time password input is required")
    passwords = parse_robinhood_passwords(
        _read_protected_file(path, description="password input", consume=True, require_tmpfs=True, fifo_timeout=fifo_timeout),
    )
    if not required_names:
        return {}
    if set(passwords) != required_names:
        raise RobinhoodCredentialError("Robinhood password input does not match required accounts")
    return passwords


def load_session_ttl(environ: Mapping[str, str] | None = None) -> int:
    """Load the bounded Robinhood session TTL."""
    environment = os.environ if environ is None else environ
    raw = environment.get(SESSION_TTL_ENV, "")
    if raw == "":
        return DEFAULT_SESSION_TTL_SECONDS
    if not raw.isascii() or not raw.isdecimal():
        raise RobinhoodCredentialError("Invalid Robinhood session TTL")
    ttl = int(raw)
    if not MIN_SESSION_TTL_SECONDS <= ttl <= MAX_SESSION_TTL_SECONDS:
        raise RobinhoodCredentialError("Robinhood session TTL must be between 300 and 86400 seconds")
    return ttl
