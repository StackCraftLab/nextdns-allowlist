from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.main import create_app
from app.nextdns import NextDNSClient

API_KEY = "a8f4e42e896ff37f181e3e8a42a9737e1423d8e7"
PROFILE = "59b6c8"
USERNAME = "admin"
PASSWORD = "correct horse battery staple"
ALLOWLIST_URL = f"https://api.nextdns.io/profiles/{PROFILE}/allowlist"

# Fast hashing parameters for tests only; production uses argon2-cffi defaults.
security.password_hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


@dataclass
class FakeNextDNS:
    """Mock NextDNS API. Records every request; responses are configurable per method."""

    entries: list[dict] = field(default_factory=list)
    get_response: httpx.Response | Exception | None = None
    post_response: httpx.Response | Exception | None = None
    requests: list[httpx.Request] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "GET":
            if isinstance(self.get_response, Exception):
                raise self.get_response
            return self.get_response or httpx.Response(200, json={"data": self.entries})
        if request.method == "POST":
            if isinstance(self.post_response, Exception):
                raise self.post_response
            if self.post_response is not None:
                return self.post_response
            body = json.loads(request.content)
            self.entries.append(body)
            return httpx.Response(200, json={"data": body})
        return httpx.Response(405)

    @property
    def posts(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == "POST"]


@pytest.fixture
def fake() -> FakeNextDNS:
    return FakeNextDNS()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        nextdns_profile_id=PROFILE,
        nextdns_api_key=API_KEY,
        app_username=USERNAME,
        secret_key="x" * 48,
        env="production",
        database_path=tmp_path / "app.db",
        cookie_secure=True,
        session_idle_minutes=30,
        session_absolute_hours=12,
    )


@pytest.fixture
def app(settings, fake):
    nextdns = NextDNSClient(API_KEY, PROFILE, transport=httpx.MockTransport(fake.handler))
    application = create_app(settings, nextdns)
    application.state.db.set_password_hash(USERNAME, security.hash_password(PASSWORD))
    return application


@pytest.fixture
def client(app) -> TestClient:
    # HTTPS base URL so the client sends Secure / __Host- cookies back.
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in page"
    return match.group(1)


def login(client: TestClient, username: str = USERNAME, password: str = PASSWORD) -> httpx.Response:
    page = client.get("/login")
    return client.post(
        "/login", data={"csrf_token": csrf_from(page.text), "username": username, "password": password}
    )


@pytest.fixture
def authed(client) -> TestClient:
    response = login(client)
    assert response.status_code == 303
    return client


def add(client: TestClient, hostname: str) -> httpx.Response:
    token = csrf_from(client.get("/").text)
    response = client.post("/add", data={"csrf_token": token, "hostname": hostname})
    return response


def flash(client: TestClient) -> str:
    return client.get("/").text
