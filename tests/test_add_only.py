"""Verify the add-only guarantee at both the HTTP and client-code level."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from tests.conftest import add

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def test_route_table_is_exactly_the_expected_set(app):
    routes = {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }
    assert routes == {
        ("GET", "/healthz"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("POST", "/logout"),
        ("GET", "/"),
        ("POST", "/add"),
        ("GET", "/allowlist"),
    }


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH"])
@pytest.mark.parametrize("path", ["/", "/add", "/allowlist", "/allowlist/example.com", "/api/allowlist", "/proxy"])
def test_no_delete_or_modify_endpoints(authed, fake, method, path):
    response = authed.request(method, path)
    assert response.status_code in (404, 405)
    assert fake.requests == []


def test_add_ignores_extra_fields_like_url_or_method(authed, fake):
    token = authed.get("/").text.split('name="csrf_token" value="')[1].split('"')[0]
    authed.post(
        "/add",
        data={
            "csrf_token": token,
            "hostname": "example.com",
            "url": "https://api.nextdns.io/profiles/59b6c8/denylist",
            "method": "DELETE",
        },
    )
    assert {(r.method, str(r.url)) for r in fake.requests} == {
        ("GET", "https://api.nextdns.io/profiles/59b6c8/allowlist"),
        ("POST", "https://api.nextdns.io/profiles/59b6c8/allowlist"),
    }


def test_only_get_and_post_ever_sent(authed, fake):
    for host in ("a.example.com", "b.example.com", "a.example.com"):
        add(authed, host)
    assert {r.method for r in fake.requests} <= {"GET", "POST"}
    assert {str(r.url) for r in fake.requests} == {"https://api.nextdns.io/profiles/59b6c8/allowlist"}


def test_client_source_contains_no_mutating_http_verbs():
    """Static check: no PUT/PATCH/DELETE call or generic request() exists anywhere in app/."""
    forbidden_attrs = {"put", "patch", "delete", "request", "send", "stream"}
    for path in APP_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in forbidden_attrs and _looks_like_http_client(node.func.value):
                    pytest.fail(f"{path.name}:{node.lineno} calls .{node.func.attr}() on an HTTP client")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value.upper() not in {"PUT", "PATCH", "DELETE"}, f"{path.name}:{node.lineno}"


def _looks_like_http_client(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in {"client", "httpx", "self._client"}


def test_client_refuses_unnormalised_hostname():
    import asyncio

    import httpx

    from app.nextdns import NextDNSClient

    client = NextDNSClient("k" * 40, "59b6c8", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(ValueError):
        asyncio.run(client.add("https://example.com"))
    with pytest.raises(ValueError):
        asyncio.run(client.add("Example.com"))


def test_client_rejects_malicious_profile_id():
    from app.nextdns import NextDNSClient

    for bad in ("59b6c8/../../account", "59b6c8?x=1", "", "a/b"):
        with pytest.raises(ValueError):
            NextDNSClient("k" * 40, bad)
