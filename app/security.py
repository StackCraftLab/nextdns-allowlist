"""Password hashing, token helpers and in-memory rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# argon2-cffi defaults to Argon2id (RFC 9106 low-memory profile: t=3, m=64 MiB, p=4).
password_hasher = PasswordHasher()
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024

# Limit concurrent Argon2 verifications so a login burst cannot exhaust memory.
_verify_slots = threading.BoundedSemaphore(2)
_dummy_hash: str | None = None


def hash_password(password: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters")
    return password_hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification: an unknown user still costs one Argon2 run."""
    global _dummy_hash
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    with _verify_slots:
        if stored_hash is None:
            if _dummy_hash is None:
                _dummy_hash = password_hasher.hash(secrets.token_urlsafe(16))
            try:
                password_hasher.verify(_dummy_hash, password)
            except VerificationError:
                pass
            return False
        try:
            return password_hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(secret_key: str, token: str) -> str:
    """Session tokens are stored only as keyed hashes, so a leaked DB yields no usable cookies."""
    return hmac.new(secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


def sign(secret_key: str, value: str, purpose: str) -> str:
    mac = hmac.new(secret_key.encode(), f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{value}.{mac}"


def verify_signed(secret_key: str, signed: str, purpose: str) -> bool:
    value, _, _ = signed.rpartition(".")
    if not value:
        return False
    return hmac.compare_digest(sign(secret_key, value, purpose), signed)


def tokens_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


class SlidingWindowLimiter:
    """Counts events per key in a sliding window; blocks the key for ``lockout`` seconds
    once ``limit`` events occur within ``window`` seconds.

    State is per process and in memory. The app runs as a single process, so this
    is sufficient; a restart resets counters (documented in SECURITY.md).
    """

    def __init__(self, limit: int, window: float, lockout: float, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window
        self.lockout = lockout
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._events[key]
        while events and events[0] <= now - self.window:
            events.popleft()
        return events

    def retry_after(self, key: str) -> int:
        """Seconds until ``key`` may try again, 0 if not blocked."""
        now = time.monotonic()
        with self._lock:
            until = self._locked_until.get(key, 0.0)
            if until > now:
                return int(until - now) + 1
            self._locked_until.pop(key, None)
            return 0

    def hit(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._events) > self.max_keys:
                self._gc(now)
            events = self._prune(key, now)
            events.append(now)
            if len(events) >= self.limit:
                self._locked_until[key] = now + self.lockout
                events.clear()

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
            self._locked_until.pop(key, None)

    def _gc(self, now: float) -> None:
        for key in list(self._events):
            if not self._prune(key, now):
                del self._events[key]
        for key, until in list(self._locked_until.items()):
            if until <= now:
                del self._locked_until[key]
