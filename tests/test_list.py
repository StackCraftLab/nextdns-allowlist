from __future__ import annotations

import httpx

from tests.conftest import API_KEY


def test_list_requires_authentication(client, fake):
    response = client.get("/allowlist")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert fake.requests == []


def test_list_shows_all_entries_sorted(authed, fake):
    fake.entries.extend([
        {"id": "zeta.example.com", "active": True},
        {"id": "alpha.example.org", "active": True},
        {"id": "off.example.net", "active": False},
    ])
    page = authed.get("/allowlist")
    assert page.status_code == 200
    assert "3 entries on the allowlist" in page.text
    assert page.text.index("alpha.example.org") < page.text.index("zeta.example.com")
    assert "disabled" in page.text


def test_list_search_filter(authed, fake):
    fake.entries.extend([{"id": "news.example.org", "active": True}, {"id": "shop.example.com", "active": True}])
    page = authed.get("/allowlist", params={"q": "NEWS"})
    assert "1 of 2 entries match" in page.text
    assert "news.example.org" in page.text
    assert "shop.example.com" not in page.text


def test_list_empty(authed, fake):
    assert "The allowlist is empty" in authed.get("/allowlist").text


def test_list_uses_only_get(authed, fake):
    authed.get("/allowlist")
    authed.get("/allowlist", params={"q": "x"})
    assert [(r.method, str(r.url)) for r in fake.requests] == [
        ("GET", "https://api.nextdns.io/profiles/59b6c8/allowlist")
    ] * 2


def test_list_escapes_upstream_values(authed, fake):
    fake.entries.append({"id": "<script>alert(1)</script>", "active": True})
    page = authed.get("/allowlist", params={"q": "<img src=x>"})
    assert "<script>alert(1)" not in page.text
    assert "<img src=x>" not in page.text


def test_list_api_errors_are_friendly(authed, fake):
    fake.get_response = httpx.Response(403, json={"errors": [{"code": "authRequired"}]})
    assert "credentials were rejected" in authed.get("/allowlist").text
    fake.get_response = httpx.ConnectError("down")
    assert "Could not reach NextDNS" in authed.get("/allowlist").text
    fake.get_response = httpx.Response(500, text=API_KEY)
    page = authed.get("/allowlist")
    assert "temporarily unavailable" in page.text
    assert API_KEY not in page.text


def test_list_page_has_no_mutating_controls(authed, fake):
    fake.entries.append({"id": "example.com", "active": True})
    page = authed.get("/allowlist").text
    # Only forms: logout (POST) and search (GET). No delete/edit actions.
    assert page.count("<form") == 2
    assert 'action="/logout"' in page and 'method="get" action="/allowlist"' in page
