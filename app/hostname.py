"""Strict hostname validation.

Policy:
* Input must be a bare hostname - no scheme, path, query, fragment, port,
  userinfo, wildcard or whitespace.
* Normalisation: surrounding whitespace is NOT silently accepted inside the
  value; leading/trailing whitespace is stripped, one trailing dot is removed,
  and the result is lower-cased.
* Internationalised domain names: only the ASCII (punycode, ``xn--``) form is
  accepted. Unicode input is rejected with a hint, to avoid IDNA2003/2008
  ambiguity and homograph surprises.
* At least two labels; the top-level label must not be all-numeric, which also
  rejects IPv4 literals. IPv6 literals are rejected by the character set.
"""

from __future__ import annotations

import re

MAX_INPUT_LENGTH = 255
MAX_HOSTNAME_LENGTH = 253
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidHostname(ValueError):
    """Raised with a user-safe message describing why the hostname was rejected."""


def normalize_hostname(raw: str) -> str:
    if not isinstance(raw, str):
        raise InvalidHostname("Enter a hostname such as example.com.")
    if len(raw) > MAX_INPUT_LENGTH:
        raise InvalidHostname("The hostname is too long.")

    value = raw.strip()
    if not value:
        raise InvalidHostname("Enter a hostname such as example.com.")
    if "://" in value or value.lower().startswith(("http:", "https:")):
        raise InvalidHostname("Enter only the hostname, without http:// or https://.")
    if any(ch in value for ch in "/?#"):
        raise InvalidHostname("Enter only the hostname, without a path, query string or fragment.")
    if any(ch.isspace() for ch in value):
        raise InvalidHostname("The hostname must not contain spaces.")
    if "@" in value:
        raise InvalidHostname("The hostname must not contain '@'.")
    if ":" in value or "[" in value:
        raise InvalidHostname("The hostname must not contain a port or an IP address.")
    if "*" in value:
        raise InvalidHostname("Wildcards are not supported; NextDNS allowlist entries already cover subdomains.")
    if not value.isascii():
        raise InvalidHostname(
            "Internationalised domain names must be entered in their ASCII (xn--) form."
        )

    value = value.lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > MAX_HOSTNAME_LENGTH:
        raise InvalidHostname("The hostname must be between 1 and 253 characters long.")

    labels = value.split(".")
    if len(labels) < 2:
        raise InvalidHostname("Enter a fully qualified hostname such as example.com.")
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            raise InvalidHostname(
                "Each part of the hostname may only contain letters, digits and hyphens, "
                "must be 1-63 characters long and must not start or end with a hyphen."
            )
    if labels[-1].isdigit():
        raise InvalidHostname("IP addresses are not supported; enter a hostname.")
    return value
