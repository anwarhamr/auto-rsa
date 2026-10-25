"""Tmpfs-only, expiring Robinhood bearer-session cache."""

# Cache validation intentionally uses fixed redacted messages and independent checks.
# ruff: file-ignore[ complex-structure, raw-string-in-exception, f-string-in-exception, too-many-branches, too-many-statements, magic-value-comparison, hardcoded-password-string, os-replace, suppressible-exception, raise-vanilla-args, type-check-without-type-error]

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from src.brokerages.robinhood_credentials import MAX_SESSION_TTL_SECONDS, SESSION_DIR_ENV, RobinhoodCredentialError, is_tmpfs

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MAX_SESSION_BYTES = 16 * 1024


class _DuplicateJsonKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class RobinhoodBearerSession:
    """Minimum reusable Robinhood bearer state."""

    token_type: str = field(repr=False)
    access_token: str = field(repr=False)
    expires_at: float

    def __repr__(self) -> str:
        """Never render bearer material."""
        return f"RobinhoodBearerSession(<redacted>, expires_at={self.expires_at!r})"


def is_valid_bearer_session(session: RobinhoodBearerSession) -> bool:
    """Return whether bearer state is safe to install in an HTTP header."""
    return session.token_type == "Bearer" and 0 < len(session.access_token) <= 8192 and all(character >= " " and character != "\x7f" for character in session.access_token) and math.isfinite(session.expires_at)


class RobinhoodSessionCache:
    """Store identity-bound bearer state only on a protected tmpfs directory."""

    def __init__(self, directory: str, *, wall_clock: Callable[[], float]) -> None:
        """Validate and retain the protected tmpfs cache directory."""
        self.directory = self._validate_directory(directory)
        self.wall_clock = wall_clock

    @classmethod
    def from_environment(cls, environ: Mapping[str, str], *, wall_clock: Callable[[], float]) -> RobinhoodSessionCache:
        """Build a cache from an explicitly configured tmpfs directory."""
        directory = environ.get(SESSION_DIR_ENV, "").strip()
        if not directory:
            raise RobinhoodCredentialError(f"{SESSION_DIR_ENV} is required for Robinhood")
        return cls(directory, wall_clock=wall_clock)

    @staticmethod
    def _validate_directory(directory: str) -> str:
        if not Path(directory).is_absolute():
            raise RobinhoodCredentialError("Robinhood session directory must be absolute")
        if os.path.realpath(directory) != directory:
            raise RobinhoodCredentialError("Robinhood session directory must not contain symlinks")
        try:
            directory_stat = os.lstat(directory)
        except OSError as exc:
            raise RobinhoodCredentialError("Unable to access Robinhood session directory") from exc
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise RobinhoodCredentialError("Robinhood session path must be a directory")
        if directory_stat.st_mode & 0o077:
            raise RobinhoodCredentialError("Robinhood session directory must not grant group or other permissions")
        if hasattr(os, "geteuid") and directory_stat.st_uid != os.geteuid():
            raise RobinhoodCredentialError("Robinhood session directory must be owned by the current user")
        if not is_tmpfs(directory):
            raise RobinhoodCredentialError("Robinhood session directory must be on tmpfs")
        return directory

    @staticmethod
    def _identity(name: str, username: str) -> str:
        return hashlib.sha256(f"{name}\0{username.casefold()}".encode()).hexdigest()

    def _path(self, name: str, username: str) -> Path:
        return Path(self.directory, f"{self._identity(name, username)}.json")

    def load(self, name: str, username: str) -> RobinhoodBearerSession | None:
        """Load a valid bearer session and remove expired or invalid state."""
        path = self._path(name, username)
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RobinhoodCredentialError("Unable to inspect Robinhood session cache") from exc
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_mode & 0o077:
            self.remove(name, username)
            raise RobinhoodCredentialError("Invalid Robinhood session cache protection")
        if hasattr(os, "geteuid") and path_stat.st_uid != os.geteuid():
            raise RobinhoodCredentialError("Invalid Robinhood session cache owner")
        if path_stat.st_size > MAX_SESSION_BYTES:
            self.remove(name, username)
            raise RobinhoodCredentialError("Invalid Robinhood session cache size")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise RobinhoodCredentialError("Unable to open Robinhood session cache") from exc
        try:
            opened_stat = os.fstat(descriptor)
            if (opened_stat.st_dev, opened_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                raise RobinhoodCredentialError("Robinhood session cache changed while opening")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read(MAX_SESSION_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            document = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
            if not isinstance(document, dict) or set(document) != {"version", "token_type", "access_token", "expires_at"}:
                raise ValueError
            if document["version"] != 1:
                raise ValueError
            token_type = document["token_type"]
            access_token = document["access_token"]
            expires_at = document["expires_at"]
            if not isinstance(token_type, str) or not isinstance(access_token, str):
                raise ValueError
            if isinstance(expires_at, bool) or not isinstance(expires_at, int | float):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError, ValueError, TypeError):
            self.remove(name, username)
            raise RobinhoodCredentialError("Invalid Robinhood session cache") from None
        session = RobinhoodBearerSession(token_type, access_token, float(expires_at))
        if not is_valid_bearer_session(session):
            self.remove(name, username)
            raise RobinhoodCredentialError("Invalid Robinhood session cache")
        now = self.wall_clock()
        if session.expires_at <= now:
            self.remove(name, username)
            return None
        if session.expires_at > now + MAX_SESSION_TTL_SECONDS:
            self.remove(name, username)
            raise RobinhoodCredentialError("Invalid Robinhood session cache expiry")
        return session

    def save(self, name: str, username: str, session: RobinhoodBearerSession) -> None:
        """Atomically save only access-token state with mode 0600."""
        if not is_valid_bearer_session(session):
            raise RobinhoodCredentialError("Invalid Robinhood session state")
        now = self.wall_clock()
        if not now < session.expires_at <= now + MAX_SESSION_TTL_SECONDS:
            raise RobinhoodCredentialError("Invalid Robinhood session expiry")
        payload = json.dumps({
            "version": 1,
            "token_type": session.token_type,
            "access_token": session.access_token,
            "expires_at": session.expires_at,
        }).encode()
        if len(payload) > MAX_SESSION_BYTES:
            raise RobinhoodCredentialError("Robinhood session state exceeds the size limit")
        descriptor, temporary_path = tempfile.mkstemp(prefix=".robinhood-", dir=self.directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(descriptor)
            os.replace(temporary_path, self._path(name, username))
        except OSError as exc:
            raise RobinhoodCredentialError("Unable to save Robinhood session cache") from exc
        finally:
            os.close(descriptor)
            try:
                Path(temporary_path).unlink()
            except OSError:
                pass

    def remove(self, name: str, username: str) -> None:
        """Remove cached bearer state for an identity."""
        try:
            self._path(name, username).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RobinhoodCredentialError("Unable to remove Robinhood session cache") from exc
