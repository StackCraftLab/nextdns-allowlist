"""Administrative CLI. Run inside the container, e.g.:

    docker compose exec app python -m app.manage set-password

Commands:
  set-password      Create or replace the admin password (prompts twice, never echoes).
                    Use --stdin to read a single line from standard input instead.
                    All existing sessions for the user are revoked.
  revoke-sessions   Log out every active session for the admin user.
  hash-password     Print an Argon2id hash for APP_ADMIN_PASSWORD_HASH (stores nothing).
                    For hosts without persistent storage, e.g. Render's free plan.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .config import ConfigError, load_settings
from .db import Database
from .security import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, hash_password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    sp = sub.add_parser("set-password", help="set the administrator password")
    sp.add_argument("--stdin", action="store_true", help="read the password from stdin (one line)")
    sub.add_parser("revoke-sessions", help="invalidate all sessions")
    hp = sub.add_parser("hash-password", help="print an Argon2id hash for APP_ADMIN_PASSWORD_HASH")
    hp.add_argument("--stdin", action="store_true", help="read the password from stdin (one line)")
    args = parser.parse_args(argv)

    if args.command == "hash-password":  # needs no configuration
        password = _prompt_password("New admin password: ", args.stdin)
        if password is None:
            return 1
        print(hash_password(password))
        return 0

    try:
        settings = load_settings(require_api_key=False)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    db = Database(settings.database_path)
    db.init()

    if args.command == "set-password":
        if settings.admin_password_hash:
            print("Note: APP_ADMIN_PASSWORD_HASH is set and takes precedence over this password.", file=sys.stderr)
        password = _prompt_password(f"New password for '{settings.app_username}': ", args.stdin)
        if password is None:
            return 1
        db.set_password_hash(settings.app_username, hash_password(password))
        revoked = db.delete_user_sessions(settings.app_username)
        print(f"Password set for '{settings.app_username}' (Argon2id). Revoked {revoked} session(s).")
        return 0

    if args.command == "revoke-sessions":
        revoked = db.delete_user_sessions(settings.app_username)
        print(f"Revoked {revoked} session(s).")
        return 0
    return 1


def _prompt_password(prompt: str, from_stdin: bool) -> str | None:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(prompt)
        if getpass.getpass("Repeat password: ") != password:
            print("Passwords do not match.", file=sys.stderr)
            return None
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        return None
    return password


if __name__ == "__main__":
    sys.exit(main())
