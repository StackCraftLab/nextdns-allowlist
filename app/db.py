"""SQLite persistence: admin credential hash, server-side sessions, recent submissions."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    csrf_token  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    flash_kind  TEXT,
    flash_text  TEXT
);
CREATE INDEX IF NOT EXISTS sessions_username ON sessions(username);
CREATE TABLE IF NOT EXISTS submissions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL,
    hostname   TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""

RECENT_LIMIT = 10
SUBMISSION_RETENTION = 200


@dataclass(frozen=True)
class Session:
    token_hash: str
    username: str
    csrf_token: str
    created_at: int
    last_seen: int


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    # --- users -------------------------------------------------------------
    def get_password_hash(self, username: str) -> str | None:
        with closing(self.connect()) as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
        return row["password_hash"] if row else None

    def set_password_hash(self, username: str, password_hash: str) -> None:
        with closing(self.connect()) as conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, "
                "updated_at = excluded.updated_at",
                (username, password_hash, int(time.time())),
            )

    def has_user(self, username: str) -> bool:
        return self.get_password_hash(username) is not None

    # --- sessions ----------------------------------------------------------
    def create_session(self, token_hash: str, username: str, csrf_token: str) -> None:
        now = int(time.time())
        with closing(self.connect()) as conn:
            conn.execute(
                "INSERT INTO sessions(token_hash, username, csrf_token, created_at, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash, username, csrf_token, now, now),
            )

    def get_session(self, token_hash: str) -> Session | None:
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT token_hash, username, csrf_token, created_at, last_seen FROM sessions "
                "WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return Session(**dict(row)) if row else None

    def touch_session(self, token_hash: str) -> None:
        with closing(self.connect()) as conn:
            conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (int(time.time()), token_hash))

    def delete_session(self, token_hash: str) -> None:
        with closing(self.connect()) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def delete_user_sessions(self, username: str) -> int:
        with closing(self.connect()) as conn:
            return conn.execute("DELETE FROM sessions WHERE username = ?", (username,)).rowcount

    def purge_expired_sessions(self, idle_seconds: int, absolute_seconds: int) -> None:
        now = int(time.time())
        with closing(self.connect()) as conn:
            conn.execute(
                "DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
                (now - idle_seconds, now - absolute_seconds),
            )

    def set_flash(self, token_hash: str, kind: str, text: str) -> None:
        with closing(self.connect()) as conn:
            conn.execute(
                "UPDATE sessions SET flash_kind = ?, flash_text = ? WHERE token_hash = ?",
                (kind, text, token_hash),
            )

    def pop_flash(self, token_hash: str) -> tuple[str, str] | None:
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT flash_kind, flash_text FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if not row or row["flash_kind"] is None:
                return None
            conn.execute(
                "UPDATE sessions SET flash_kind = NULL, flash_text = NULL WHERE token_hash = ?", (token_hash,)
            )
        return row["flash_kind"], row["flash_text"]

    # --- submissions -------------------------------------------------------
    def record_submission(self, username: str, hostname: str, outcome: str) -> None:
        with closing(self.connect()) as conn:
            conn.execute(
                "INSERT INTO submissions(username, hostname, outcome, created_at) VALUES (?, ?, ?, ?)",
                (username, hostname, outcome, int(time.time())),
            )
            conn.execute(
                "DELETE FROM submissions WHERE id NOT IN "
                "(SELECT id FROM submissions ORDER BY id DESC LIMIT ?)",
                (SUBMISSION_RETENTION,),
            )

    def recent_submissions(self, limit: int = RECENT_LIMIT) -> list[sqlite3.Row]:
        with closing(self.connect()) as conn:
            return conn.execute(
                "SELECT hostname, outcome, created_at FROM submissions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
