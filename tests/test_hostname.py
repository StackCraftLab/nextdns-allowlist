import pytest

from app.hostname import InvalidHostname, normalize_hostname


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("subdomain.example.com", "subdomain.example.com"),
        ("news.example.org", "news.example.org"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a-b.c-d.io", "a-b.c-d.io"),
        ("1password.com", "1password.com"),
        ("a" * 63 + ".com", "a" * 63 + ".com"),
    ],
)
def test_valid(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://example.com",
        "http://example.com",
        "example.com/path",
        "example.com?q=1",
        "example.com#frag",
        "example.com:443",
        "user@example.com",
        "exa mple.com",
        "example.com\n.evil",
        "localhost",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "example..com",
        ".example.com",
        "example.com..",
        "*.example.com",
        "192.168.1.1",
        "[::1]",
        "bücher.example",
        "a" * 64 + ".com",
        ("a" * 60 + ".") * 5 + "com",
        "x" * 300,
        "../../profiles/59b6c8",
        "example.com/../denylist",
        "example.com\x00",
    ],
)
def test_invalid(raw):
    with pytest.raises(InvalidHostname):
        normalize_hostname(raw)
