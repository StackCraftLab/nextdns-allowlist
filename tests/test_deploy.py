"""Hosting-related behaviour: env-supplied password hash (Render) and Host header checks."""

from __future__ import annotations

import io

import httpx
from fastapi.testclient import TestClient

from app import security
from app.main import create_app
from app.nextdns import NextDNSClient
from tests.conftest import USERNAME, login


def _app(settings, fake, **overrides):
    s = settings.__class__(**{**settings.__dict__, **overrides})
    return create_app(s, NextDNSClient("k" * 40, "59b6c8", transport=httpx.MockTransport(fake.handler)))


def test_env_password_hash_allows_login_without_db_user(settings, fake):
    hashed = security.hash_password("render passphrase 42")
    app = _app(settings, fake, admin_password_hash=hashed)
    assert app.state.db.get_password_hash(USERNAME) is None
    c = TestClient(app, base_url="https://testserver", follow_redirects=False)
    assert "No administrator account" not in c.get("/login").text
    assert login(c, password="wrong password!!").status_code == 401
    assert login(c, password="render passphrase 42").status_code == 303


def test_env_password_hash_overrides_db(app, settings, fake):
    from tests.conftest import PASSWORD

    app2 = _app(settings, fake, admin_password_hash=security.hash_password("the env one wins"))
    c = TestClient(app2, base_url="https://testserver", follow_redirects=False)
    assert login(c, password=PASSWORD).status_code == 401
    c.cookies.clear()
    assert login(c, password="the env one wins").status_code == 303


def test_config_rejects_non_argon2id_hash(monkeypatch):
    import pytest

    from app.config import ConfigError, load_settings

    monkeypatch.setenv("NEXTDNS_PROFILE_ID", "59b6c8")
    monkeypatch.setenv("NEXTDNS_API_KEY", "k" * 40)
    monkeypatch.setenv("APP_USERNAME", "admin")
    monkeypatch.setenv("APP_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("APP_ADMIN_PASSWORD_HASH", "plaintext-password")
    with pytest.raises(ConfigError):
        load_settings()


def test_manage_hash_password_prints_hash_only(monkeypatch, capsys):
    from app import manage

    monkeypatch.setattr("sys.stdin", io.StringIO("a long enough passphrase\n"))
    assert manage.main(["hash-password", "--stdin"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("$argon2id$")
    assert "a long enough passphrase" not in out
    assert security.verify_password(out, "a long enough passphrase")


def test_host_allowlist(settings, fake, monkeypatch):
    monkeypatch.setenv("APP_ALLOWED_HOSTS", "allowlist.onrender.com")
    app = _app(settings, fake)
    good = TestClient(app, base_url="https://allowlist.onrender.com", follow_redirects=False)
    evil = TestClient(app, base_url="https://evil.example", follow_redirects=False)
    assert good.get("/login").status_code == 200
    assert evil.get("/login").status_code == 400
    assert evil.post("/add", data={"hostname": "example.com"}).status_code == 400
    # Platform health checks may use any Host header.
    assert evil.get("/healthz").status_code == 200
    assert fake.requests == []


def test_render_hostname_used_as_default_allowed_host(settings, fake, monkeypatch):
    monkeypatch.delenv("APP_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "my-allowlist.onrender.com")
    app = _app(settings, fake)
    assert TestClient(app, base_url="https://my-allowlist.onrender.com").get("/login").status_code == 200
    assert TestClient(app, base_url="https://other.example").get("/login").status_code == 400
