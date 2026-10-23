"""Fail-closed credential and browser-profile configuration for Chase."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

CREDENTIALS_FILE_ENV = "RSA_BROKER_CREDENTIALS_FILE"
LEGACY_CREDENTIALS_ENV = "CHASE"
ALLOW_LEGACY_ENV = "RSA_ALLOW_LEGACY_ENV_CREDENTIALS"
ALLOW_DURABLE_PROFILE_ENV = "RSA_CHASE_ALLOW_DURABLE_PROFILE"
DURABLE_PROFILE_DIR_ENV = "RSA_CHASE_PROFILE_DIR"
MAX_CREDENTIAL_BYTES = 64 * 1024
_MOUNT_POINT_INDEX = 4
_MAX_LEGACY_FIELDS = 4
_PHONE_LAST_FOUR = re.compile(r"^[0-9]{4}$")


class ChaseCredentialError(RuntimeError):
    """Report a credential configuration problem without exposing secrets."""


@dataclass(frozen=True, repr=False)
class ChaseCredential:
    """One validated Chase login; its representation is always redacted."""

    username: str = field(repr=False)
    password: str = field(repr=False)
    phone_last_four: str = field(repr=False)
    debug: bool = False

    def __repr__(self) -> str:
        """Never render credential values."""
        return "ChaseCredential(<redacted>)"


class _DuplicateJsonKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


def _require_exact_keys(value: Mapping[str, object], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ChaseCredentialError(f"Invalid Chase credential {context} fields")


def _parse_account(value: object) -> ChaseCredential:
    if not isinstance(value, dict):
        raise ChaseCredentialError("Invalid Chase credential account")
    required = {"username", "password", "phone_last_four", "debug"}
    _require_exact_keys(value, required, "account")
    username = value["username"]
    password = value["password"]
    phone_last_four = value["phone_last_four"]
    debug = value["debug"]
    if not isinstance(username, str) or not username:
        raise ChaseCredentialError("Invalid Chase credential username")
    if not isinstance(password, str) or not password:
        raise ChaseCredentialError("Invalid Chase credential password")
    if not isinstance(phone_last_four, str) or _PHONE_LAST_FOUR.fullmatch(phone_last_four) is None:
        raise ChaseCredentialError("Invalid Chase credential phone_last_four")
    if not isinstance(debug, bool):
        raise ChaseCredentialError("Invalid Chase credential debug flag")
    return ChaseCredential(username, password, phone_last_four, debug)


def parse_chase_credentials(payload: bytes) -> tuple[ChaseCredential, ...]:
    """Validate a versioned Chase JSON payload."""
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError):
        # JSON decoder errors can echo source fragments containing secrets.
        raise ChaseCredentialError("Invalid Chase credential JSON") from None
    if not isinstance(document, dict):
        raise ChaseCredentialError("Invalid Chase credential document")
    _require_exact_keys(document, {"version", "broker", "accounts"}, "document")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ChaseCredentialError("Unsupported Chase credential schema version")
    if document["broker"] != "chase":
        raise ChaseCredentialError("Chase credential broker must be 'chase'")
    accounts = document["accounts"]
    if not isinstance(accounts, list) or not accounts:
        raise ChaseCredentialError("Chase credential accounts must be a non-empty list")
    return tuple(_parse_account(account) for account in accounts)


def _decode_mount_path(value: str) -> str:
    # Linux mountinfo uses octal escapes for whitespace and backslashes.
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _is_tmpfs(path: str) -> bool:
    """Return whether path is on a Linux tmpfs mount, failing closed elsewhere."""
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


def _read_and_consume_credentials(path: str) -> bytes:
    if not Path(path).is_absolute():
        raise ChaseCredentialError(f"{CREDENTIALS_FILE_ENV} must name an absolute path")
    try:
        path_stat = os.lstat(path)
    except OSError as exc:
        raise ChaseCredentialError("Unable to open Chase credential input") from exc
    is_regular = stat.S_ISREG(path_stat.st_mode)
    is_fifo = stat.S_ISFIFO(path_stat.st_mode)
    if not (is_regular or is_fifo):
        raise ChaseCredentialError("Chase credential input must be a FIFO or regular file")
    if path_stat.st_mode & 0o077:
        raise ChaseCredentialError("Chase credential input must not grant group or other permissions")
    if hasattr(os, "geteuid") and path_stat.st_uid != os.geteuid():
        raise ChaseCredentialError("Chase credential input must be owned by the current user")
    if is_regular and not _is_tmpfs(path):
        raise ChaseCredentialError("Regular Chase credential input must be on tmpfs")
    if is_regular and path_stat.st_size > MAX_CREDENTIAL_BYTES:
        raise ChaseCredentialError("Chase credential input exceeds the size limit")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ChaseCredentialError("Unable to open Chase credential input") from exc
    accepted = False
    try:
        opened_stat = os.fstat(descriptor)
        if (opened_stat.st_dev, opened_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise ChaseCredentialError("Chase credential input changed while opening")
        opened_is_regular = stat.S_ISREG(opened_stat.st_mode)
        if not (opened_is_regular or stat.S_ISFIFO(opened_stat.st_mode)):
            raise ChaseCredentialError("Chase credential input type changed while opening")
        if opened_is_regular and not _is_tmpfs(f"/proc/self/fd/{descriptor}"):
            raise ChaseCredentialError("Opened Chase credential input is not on tmpfs")
        if opened_stat.st_mode & 0o077:
            raise ChaseCredentialError("Chase credential input permissions changed while opening")
        if hasattr(os, "geteuid") and opened_stat.st_uid != os.geteuid():
            raise ChaseCredentialError("Chase credential input owner changed while opening")
        accepted = True
        with suppress(OSError):
            Path(path).unlink()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_CREDENTIAL_BYTES + 1)
        if len(payload) > MAX_CREDENTIAL_BYTES:
            raise ChaseCredentialError("Chase credential input exceeds the size limit")
        return payload
    finally:
        os.close(descriptor)
        if accepted:
            with suppress(OSError):
                Path(path).unlink()


def _parse_legacy_credentials(value: str) -> tuple[ChaseCredential, ...]:
    credentials: list[ChaseCredential] = []
    for raw_account in value.split(","):
        fields = raw_account.split(":")
        if len(fields) not in {3, 4}:
            raise ChaseCredentialError("Invalid legacy Chase credential format")
        debug = False
        if len(fields) == _MAX_LEGACY_FIELDS:
            normalized = fields[3].strip().lower()
            if normalized not in {"true", "false"}:
                raise ChaseCredentialError("Invalid legacy Chase debug flag")
            debug = normalized == "true"
        credentials.append(
            _parse_account({
                "username": fields[0],
                "password": fields[1],
                "phone_last_four": fields[2],
                "debug": debug,
            }),
        )
    return tuple(credentials)


def load_chase_credentials(environ: Mapping[str, str] | None = None) -> tuple[ChaseCredential, ...] | None:
    """Load Chase credentials from a consumed file or explicitly enabled legacy env."""
    environment = os.environ if environ is None else environ
    credentials_path = environment.get(CREDENTIALS_FILE_ENV, "").strip()
    legacy_value = environment.get(LEGACY_CREDENTIALS_ENV, "")
    if credentials_path:
        if legacy_value:
            raise ChaseCredentialError("Configure only one Chase credential source")
        return parse_chase_credentials(_read_and_consume_credentials(credentials_path))
    if not legacy_value:
        return None
    if environment.get(ALLOW_LEGACY_ENV, "").strip().lower() != "true":
        raise ChaseCredentialError(f"{LEGACY_CREDENTIALS_ENV} is disabled; use {CREDENTIALS_FILE_ENV} or explicitly enable legacy credentials")
    return _parse_legacy_credentials(legacy_value.strip())


def _validate_durable_profile(path: str) -> str:
    if not Path(path).is_absolute():
        raise ChaseCredentialError(f"{DURABLE_PROFILE_DIR_ENV} must name an absolute path")
    if os.path.realpath(path) != path:
        raise ChaseCredentialError("Chase durable profile directory must not contain symlinks")
    try:
        directory_stat = os.lstat(path)
    except OSError as exc:
        raise ChaseCredentialError("Unable to access Chase durable profile directory") from exc
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise ChaseCredentialError("Chase durable profile path must be a directory")
    if directory_stat.st_mode & 0o077:
        raise ChaseCredentialError("Chase durable profile directory must not grant group or other permissions")
    if hasattr(os, "geteuid") and directory_stat.st_uid != os.geteuid():
        raise ChaseCredentialError("Chase durable profile directory must be owned by the current user")
    return path


@contextmanager
def chase_profile_directory(environ: Mapping[str, str] | None = None) -> Iterator[str]:
    """Yield a protected durable profile only with opt-in; otherwise an ephemeral one.

    Yields:
        A protected directory for the Chase browser profile.

    """
    environment = os.environ if environ is None else environ
    durable_allowed = environment.get(ALLOW_DURABLE_PROFILE_ENV, "").strip().lower() == "true"
    durable_path = environment.get(DURABLE_PROFILE_DIR_ENV, "").strip()
    if durable_allowed:
        if not durable_path:
            raise ChaseCredentialError(f"{DURABLE_PROFILE_DIR_ENV} is required for durable Chase profiles")
        yield _validate_durable_profile(durable_path)
        return
    if durable_path:
        raise ChaseCredentialError(f"{ALLOW_DURABLE_PROFILE_ENV}=true is required for durable Chase profiles")
    with tempfile.TemporaryDirectory(prefix="rsa-chase-profile-") as directory:
        Path(directory).chmod(0o700)
        yield directory
