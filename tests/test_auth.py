from __future__ import annotations

import time

from app import security
from tests.conftest import PASSWORD, USERNAME, csrf_from, login


def test_successful_login_redirects_and_sets_session(client):
    response = login(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "__Host-session" in response.cookies
    page = client.get("/")
    assert page.status_code == 200
    assert "Add to Allowlist" in page.text


def test_failed_login_wrong_password(client):
    response = login(client, password="wrong password!!")
    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert "__Host-session" not in response.cookies
    assert client.get("/").status_code == 303


def test_failed_login_unknown_user_same_message(client):
    response = login(client, username="root", password=PASSWORD)
    assert response.status_code == 401
    assert "Invalid username or password" in response.text


def test_no_default_credentials_before_setup(settings, fake):
    import httpx
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.nextdns import NextDNSClient

    settings2 = settings.__class__(**{**settings.__dict__, "database_path": settings.database_path.with_name("empty.db")})
    app = create_app(settings2, NextDNSClient("k" * 40, "59b6c8", transport=httpx.MockTransport(fake.handler)))
    c = TestClient(app, base_url="https://testserver", follow_redirects=False)
    page = c.get("/login")
    assert "No administrator account has been set up" in page.text
    for pw in ("admin", "password", "", "changeme"):
        assert login(c, password=pw).status_code in (401, 429)


def test_protected_pages_require_authentication(client, fake):
    assert client.get("/").status_code == 303
    assert client.get("/").headers["location"] == "/login"
    response = client.post("/add", data={"hostname": "example.com", "csrf_token": "x"})
    assert response.status_code == 401
    assert fake.requests == []


def test_logout_invalidates_session_server_side(authed, app):
    token = authed.cookies.get("__Host-session")
    csrf = csrf_from(authed.get("/").text)
    response = authed.post("/logout", data={"csrf_token": csrf})
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    # Replaying the old cookie must not work: the session is gone from the DB.
    authed.cookies.set("__Host-session", token, domain="testserver.local", path="/")
    assert authed.get("/").status_code == 303
    assert app.state.db.get_session(security.token_digest("x" * 48, token)) is None


def test_logout_requires_csrf(authed):
    response = authed.post("/logout", data={"csrf_token": "bogus"})
    assert response.status_code == 403
    assert authed.get("/").status_code == 200


def test_session_cookie_attributes(client):
    response = login(client)
    header = next(v for k, v in response.headers.multi_items() if k == "set-cookie" and v.startswith("__Host-session="))
    lowered = header.lower()
    assert "httponly" in lowered
    assert "secure" in lowered
    assert "samesite=strict" in lowered
    assert "path=/" in lowered
    assert "domain=" not in lowered


def test_development_mode_cookie_name_without_secure(settings, fake):
    import httpx
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.nextdns import NextDNSClient

    dev = settings.__class__(**{**settings.__dict__, "env": "development", "cookie_secure": False})
    app = create_app(dev, NextDNSClient("k" * 40, "59b6c8", transport=httpx.MockTransport(fake.handler)))
    app.state.db.set_password_hash(USERNAME, security.hash_password(PASSWORD))
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    response = login(c)
    header = next(v for k, v in response.headers.multi_items() if k == "set-cookie" and v.startswith("session="))
    assert "httponly" in header.lower() and "samesite=strict" in header.lower()


def test_session_idle_timeout(authed, app):
    token = authed.cookies.get("__Host-session")
    digest = security.token_digest("x" * 48, token)
    with app.state.db.connect() as conn:
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (int(time.time()) - 31 * 60, digest))
    assert authed.get("/").status_code == 303


def test_session_token_rotates_on_login(client):
    first = login(client).cookies.get("__Host-session")
    client.cookies.clear()
    second = login(client).cookies.get("__Host-session")
    assert first and second and first != second


def test_session_token_stored_hashed(authed, app):
    token = authed.cookies.get("__Host-session")
    with app.state.db.connect() as conn:
        rows = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert token not in rows


def test_login_csrf_required(client):
    client.get("/login")
    response = client.post("/login", data={"csrf_token": "forged", "username": USERNAME, "password": PASSWORD})
    assert response.status_code == 403
    assert "__Host-session" not in response.cookies


def test_login_csrf_cookie_must_match_form(client):
    page = client.get("/login")
    token = csrf_from(page.text)
    client.cookies.clear()
    response = client.post("/login", data={"csrf_token": token, "username": USERNAME, "password": PASSWORD})
    assert response.status_code == 403


def test_add_requires_csrf(authed, fake):
    response = authed.post("/add", data={"csrf_token": "forged", "hostname": "example.com"})
    assert response.status_code == 403
    response = authed.post("/add", data={"hostname": "example.com"})
    assert response.status_code == 403
    assert fake.requests == []


def test_login_rate_limit_locks_out(client):
    for _ in range(10):
        assert login(client, password="wrong password!!").status_code == 401
    response = login(client)  # correct password, but locked out
    assert response.status_code == 429
    assert "Too many failed attempts" in response.text
    assert int(response.headers["Retry-After"]) > 0
    assert "__Host-session" not in response.cookies


def test_password_rehash_and_hash_format(app):
    stored = app.state.db.get_password_hash(USERNAME)
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_manage_set_password(tmp_path, monkeypatch, capsys):
    import io

    from app import manage
    from app.db import Database

    db_path = tmp_path / "cli.db"
    monkeypatch.setenv("NEXTDNS_PROFILE_ID", "59b6c8")
    monkeypatch.setenv("APP_USERNAME", "admin")
    monkeypatch.setenv("APP_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("APP_DATABASE_PATH", str(db_path))
    monkeypatch.delenv("NEXTDNS_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert manage.main(["set-password", "--stdin"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("a much longer passphrase\n"))
    assert manage.main(["set-password", "--stdin"]) == 0
    stored = Database(db_path).get_password_hash("admin")
    assert stored.startswith("$argon2id$")
    assert security.verify_password(stored, "a much longer passphrase")
