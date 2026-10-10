"""Application configuration loaded from environment variables or Docker secrets.

Every secret can be supplied either directly (``NAME``) or via a file path
(``NAME_FILE``), which is how Docker/Compose secrets are mounted.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
MIN_SECRET_KEY_LENGTH = 32


class ConfigError(RuntimeError):
    """Raised when configuration is missing or invalid. Never includes secret values."""


def _read(name: str, default: str | None = None) -> str | None:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"Cannot read {name}_FILE ({exc.strerror})") from None
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _bool(name: str, default: bool) -> bool:
    value = _read(name)
    if value is None or value == "":
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    nextdns_profile_id: str
    nextdns_api_key: str
    app_username: str
    secret_key: str
    env: str
    database_path: Path
    cookie_secure: bool
    session_idle_minutes: int
    session_absolute_hours: int
    admin_password_hash: str | None = None

    def __repr__(self) -> str:  # never leak secrets via repr()/logging
        return (
            f"Settings(profile_id={self.nextdns_profile_id!r}, username={self.app_username!r}, "
            f"env={self.env!r}, database_path={str(self.database_path)!r}, "
            f"cookie_secure={self.cookie_secure!r})"
        )

    @property
    def session_cookie_name(self) -> str:
        # The __Host- prefix forces Secure, Path=/ and no Domain in the browser.
        return "__Host-session" if self.cookie_secure else "session"

    @property
    def login_csrf_cookie_name(self) -> str:
        return "__Host-login_csrf" if self.cookie_secure else "login_csrf"


def load_settings(require_api_key: bool = True) -> Settings:
    env = (_read("APP_ENV", "production") or "production").lower()
    if env not in {"production", "development"}:
        raise ConfigError("APP_ENV must be 'production' or 'development'")

    profile_id = _read("NEXTDNS_PROFILE_ID") or ""
    if not PROFILE_ID_RE.fullmatch(profile_id):
        raise ConfigError("NEXTDNS_PROFILE_ID is missing or malformed")

    api_key = _read("NEXTDNS_API_KEY") or ""
    if require_api_key and (not api_key or api_key == "replace_with_api_key"):
        raise ConfigError("NEXTDNS_API_KEY is not set")
    if api_key and not re.fullmatch(r"[A-Za-z0-9]{8,128}", api_key):
        raise ConfigError("NEXTDNS_API_KEY has an unexpected format")

    username = _read("APP_USERNAME") or ""
    if not USERNAME_RE.fullmatch(username):
        raise ConfigError("APP_USERNAME is missing or contains unsupported characters")

    secret_key = _read("APP_SECRET_KEY") or ""
    if len(secret_key) < MIN_SECRET_KEY_LENGTH or secret_key.startswith("replace_with"):
        raise ConfigError(f"APP_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} random characters")

    def _int(name: str, default: int, lo: int, hi: int) -> int:
        raw = _read(name)
        try:
            value = int(raw) if raw else default
        except ValueError:
            raise ConfigError(f"{name} must be an integer") from None
        if not lo <= value <= hi:
            raise ConfigError(f"{name} must be between {lo} and {hi}")
        return value

    admin_hash = _read("APP_ADMIN_PASSWORD_HASH") or None
    if admin_hash and not admin_hash.startswith("$argon2id$"):
        raise ConfigError("APP_ADMIN_PASSWORD_HASH must be an Argon2id hash (python -m app.manage hash-password)")

    return Settings(
        nextdns_profile_id=profile_id,
        nextdns_api_key=api_key,
        app_username=username,
        secret_key=secret_key,
        env=env,
        database_path=Path(_read("APP_DATABASE_PATH", "/data/app.db") or "/data/app.db"),
        # Secure cookies are mandatory in production; only development may disable them.
        cookie_secure=True if env == "production" else _bool("APP_COOKIE_SECURE", False),
        session_idle_minutes=_int("APP_SESSION_IDLE_MINUTES", 30, 5, 24 * 60),
        session_absolute_hours=_int("APP_SESSION_ABSOLUTE_HOURS", 12, 1, 7 * 24),
        admin_password_hash=admin_hash,
    )
