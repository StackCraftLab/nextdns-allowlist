from __future__ import annotations

import json
import re

import httpx

from tests.conftest import ALLOWLIST_URL, API_KEY, add, flash


def test_valid_hostname_is_added(authed, fake):
    response = add(authed, "Example.com.")
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert len(fake.posts) == 1
    post = fake.posts[0]
    assert str(post.url) == ALLOWLIST_URL
    assert post.headers["X-Api-Key"] == API_KEY
    assert json.loads(post.content) == {"id": "example.com", "active": True}
    page = flash(authed)
    assert "example.com was added to the allowlist" in page
    assert "Recent submissions" in page


def test_invalid_hostname_rejected_before_api_call(authed, fake):
    for bad in ("https://example.com", "example.com/x", "example.com:8080", "not a host", "localhost"):
        assert add(authed, bad).status_code == 303
        assert "msg error" in flash(authed)
    assert fake.requests == []


def test_flash_is_escaped(authed, fake):
    add(authed, "<script>alert(1)</script>")
    page = flash(authed)
    assert "<script>alert(1)" not in page


def test_duplicate_detected_via_get(authed, fake):
    fake.entries.append({"id": "example.com", "active": True})
    add(authed, "example.com")
    assert fake.posts == []
    assert "already on the allowlist" in flash(authed)


def test_duplicate_disabled_entry_is_not_modified(authed, fake):
    fake.entries.append({"id": "example.com", "active": False})
    add(authed, "example.com")
    assert [r.method for r in fake.requests] == ["GET"]
    assert "disabled" in flash(authed)


def test_duplicate_reported_by_api_error(authed, fake):
    fake.post_response = httpx.Response(200, json={"errors": [{"code": "duplicate"}]})
    add(authed, "example.com")
    assert "already on the allowlist" in flash(authed)


def test_duplicate_reported_by_409(authed, fake):
    fake.post_response = httpx.Response(409)
    add(authed, "example.com")
    assert "already on the allowlist" in flash(authed)


def test_api_validation_error_with_200_status_is_not_success(authed, fake):
    fake.post_response = httpx.Response(200, json={"errors": [{"code": "invalid", "detail": "bad"}]})
    add(authed, "example.com")
    page = flash(authed)
    assert "NextDNS rejected example.com" in page
    assert "was added" not in page


def test_invalid_api_key(authed, fake):
    # Exact response observed from the live API for a bad/missing key.
    fake.get_response = httpx.Response(403, json={"errors": [{"code": "authRequired"}]})
    add(authed, "example.com")
    page = flash(authed)
    assert "credentials were rejected" in page
    assert fake.posts == []


def test_unauthorized_on_post(authed, fake):
    fake.post_response = httpx.Response(401)
    add(authed, "example.com")
    assert "credentials were rejected" in flash(authed)


def test_profile_not_found(authed, fake):
    fake.get_response = httpx.Response(404)
    add(authed, "example.com")
    assert "profile was not found" in flash(authed)


def test_rate_limited(authed, fake):
    fake.post_response = httpx.Response(429, headers={"Retry-After": "30"})
    add(authed, "example.com")
    assert "rate limiting" in flash(authed)


def test_network_failure(authed, fake):
    fake.get_response = httpx.ConnectError("boom")
    add(authed, "example.com")
    assert "Could not reach NextDNS" in flash(authed)


def test_timeout(authed, fake):
    fake.post_response = httpx.ReadTimeout("slow")
    add(authed, "example.com")
    assert "Could not reach NextDNS" in flash(authed)


def test_upstream_5xx(authed, fake):
    fake.post_response = httpx.Response(502, text="<html>bad gateway</html>")
    add(authed, "example.com")
    page = flash(authed)
    assert "temporarily unavailable" in page
    assert "bad gateway" not in page


def test_unexpected_payload(authed, fake):
    fake.get_response = httpx.Response(200, text="not json")
    add(authed, "example.com")
    assert "unexpected response" in flash(authed)
    assert fake.posts == []


def test_redirects_not_followed(authed, fake):
    fake.post_response = httpx.Response(302, headers={"Location": "https://evil.example/"})
    add(authed, "example.com")
    assert "unexpected response" in flash(authed)
    assert all(r.url.host == "api.nextdns.io" for r in fake.requests)


def test_add_rate_limit_per_user(authed, fake):
    for i in range(30):
        add(authed, f"h{i}.example.com")
    add(authed, "one-too-many.example.com")
    assert "Too many submissions" in flash(authed)
    assert len(fake.posts) == 30


def test_oversized_and_wrong_content_type_rejected(authed, fake):
    big = authed.post("/add", content=b"hostname=" + b"a" * 10_000,
                      headers={"content-type": "application/x-www-form-urlencoded"})
    assert big.status_code == 413
    js = authed.post("/add", json={"hostname": "example.com"})
    assert js.status_code == 415
    assert fake.requests == []


def test_api_key_never_reaches_browser(authed, fake, client):
    responses = [
        authed.get("/"),
        authed.get("/login"),
        authed.get("/healthz"),
        authed.get("/static/style.css"),
        authed.get("/does-not-exist"),
        add(authed, "example.com"),
        authed.get("/"),
    ]
    fake.post_response = httpx.Response(500, text=API_KEY)  # upstream echoes the key
    add(authed, "leak.example.com")
    responses.append(authed.get("/"))
    for r in responses:
        assert API_KEY not in r.text
        assert API_KEY not in str(r.headers)
    assert API_KEY not in repr(authed.app.state.nextdns)
    assert API_KEY not in repr(authed.app.state.settings)


def test_api_key_not_logged(authed, fake, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    fake.get_response = httpx.ConnectError(f"failed with key {API_KEY}")
    add(authed, "example.com")
    fake.get_response = None
    add(authed, "example.org")
    assert API_KEY not in caplog.text


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers(client):
    response = client.get("/login")
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "max-age" in response.headers["strict-transport-security"]
    assert response.headers["cache-control"] == "no-store"
    assert "<script" not in response.text


def test_no_open_redirect_after_login(client):
    from tests.conftest import PASSWORD, USERNAME, csrf_from

    page = client.get("/login?next=https://evil.example")
    r = client.post("/login?next=https://evil.example",
                    data={"csrf_token": csrf_from(page.text), "username": USERNAME, "password": PASSWORD})
    assert r.headers["location"] == "/"


def test_api_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
