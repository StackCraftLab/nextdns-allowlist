"""Minimal, add-only NextDNS API client.

Security properties (enforced by construction, verified by tests):
* The base URL is a constant; the only path ever requested is
  ``/profiles/<configured profile id>/allowlist``.
* Only two HTTP methods are ever used: GET (read the allowlist, to detect
  duplicates and to display it) and POST (append one entry). There is deliberately no code path
  for PUT (replace array), PATCH (edit entry) or DELETE (remove entry).
* The API key is sent only in the ``X-Api-Key`` header and is never logged,
  returned or included in exception messages.

Reference: https://nextdns.github.io/api/ - array endpoints support GET/PUT/POST,
children support PATCH/DELETE. User errors may be returned as HTTP 200 *or* 400
with an ``{"errors": [...]}`` body, so a 2xx status alone is not success.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass

import httpx

from .config import PROFILE_ID_RE
from .hostname import normalize_hostname

API_BASE_URL = "https://api.nextdns.io"
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

log = logging.getLogger("app.nextdns")


class Outcome(enum.Enum):
    ADDED = "added"
    ALREADY_PRESENT = "already_present"
    ALREADY_PRESENT_DISABLED = "already_present_disabled"
    REJECTED = "rejected"
    AUTH_FAILED = "auth_failed"
    PROFILE_NOT_FOUND = "profile_not_found"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_ERROR = "upstream_error"
    NETWORK_ERROR = "network_error"
    UNEXPECTED = "unexpected"
    LISTED = "listed"

    @property
    def ok(self) -> bool:
        return self in {Outcome.ADDED, Outcome.ALREADY_PRESENT, Outcome.ALREADY_PRESENT_DISABLED, Outcome.LISTED}


USER_MESSAGES: dict[Outcome, str] = {
    Outcome.ADDED: "{host} was added to the allowlist.",
    Outcome.ALREADY_PRESENT: "{host} is already on the allowlist. Nothing was changed.",
    Outcome.ALREADY_PRESENT_DISABLED: (
        "{host} is already on the allowlist but is disabled. This application cannot modify "
        "existing entries; ask the administrator to enable it in the NextDNS dashboard."
    ),
    Outcome.REJECTED: "NextDNS rejected {host}. Check the hostname and try again.",
    Outcome.AUTH_FAILED: "The server's NextDNS credentials were rejected. Please contact the administrator.",
    Outcome.PROFILE_NOT_FOUND: "The configured NextDNS profile was not found. Please contact the administrator.",
    Outcome.RATE_LIMITED: "NextDNS is rate limiting requests. Please wait a minute and try again.",
    Outcome.UPSTREAM_ERROR: "NextDNS is temporarily unavailable. Please try again later.",
    Outcome.NETWORK_ERROR: "Could not reach NextDNS. Please try again later.",
    Outcome.UNEXPECTED: "NextDNS returned an unexpected response. Nothing is known to have changed.",
    Outcome.LISTED: "",
}


@dataclass(frozen=True)
class AddResult:
    outcome: Outcome
    hostname: str

    @property
    def message(self) -> str:
        return USER_MESSAGES[self.outcome].format(host=self.hostname)


@dataclass(frozen=True)
class Entry:
    hostname: str
    active: bool


@dataclass(frozen=True)
class ListResult:
    outcome: Outcome
    entries: list[Entry]

    @property
    def message(self) -> str:
        return USER_MESSAGES[self.outcome].format(host="the hostname")


class _Failure(Exception):
    def __init__(self, outcome: Outcome) -> None:
        super().__init__(outcome.value)
        self.outcome = outcome


_DUPLICATE_HINTS = ("duplicate", "exist", "already", "conflict")


class NextDNSClient:
    def __init__(
        self,
        api_key: str,
        profile_id: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not PROFILE_ID_RE.fullmatch(profile_id):
            raise ValueError("invalid profile id")
        self._api_key = api_key
        self._url = f"{API_BASE_URL}/profiles/{profile_id}/allowlist"
        self._transport = transport

    def __repr__(self) -> str:
        return f"NextDNSClient(url={self._url!r})"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
            transport=self._transport,
            headers={
                "X-Api-Key": self._api_key,
                "Accept": "application/json",
                "User-Agent": "nextdns-allowlist-manager/1.0",
            },
        )

    async def add(self, hostname: str) -> AddResult:
        # Defence in depth: the caller must already have validated the hostname,
        # but the client refuses anything that is not a normalised hostname.
        if normalize_hostname(hostname) != hostname:
            raise ValueError("hostname must be normalised before calling the client")

        try:
            async with self._client() as client:
                existing = await self._find(client, hostname)
                if existing is not None:
                    outcome = Outcome.ALREADY_PRESENT if existing else Outcome.ALREADY_PRESENT_DISABLED
                    return AddResult(outcome, hostname)
                return AddResult(await self._post(client, hostname), hostname)
        except _Failure as failure:
            return AddResult(failure.outcome, hostname)
        except httpx.TimeoutException:
            log.warning("NextDNS request timed out")
            return AddResult(Outcome.NETWORK_ERROR, hostname)
        except httpx.TransportError as exc:
            log.warning("NextDNS request failed: %s", type(exc).__name__)
            return AddResult(Outcome.NETWORK_ERROR, hostname)

    async def list_entries(self) -> ListResult:
        """Read-only: return the current allowlist entries (GET only)."""
        try:
            async with self._client() as client:
                return ListResult(Outcome.LISTED, await self._fetch(client))
        except _Failure as failure:
            return ListResult(failure.outcome, [])
        except httpx.TimeoutException:
            log.warning("NextDNS request timed out")
            return ListResult(Outcome.NETWORK_ERROR, [])
        except httpx.TransportError as exc:
            log.warning("NextDNS request failed: %s", type(exc).__name__)
            return ListResult(Outcome.NETWORK_ERROR, [])

    async def _fetch(self, client: httpx.AsyncClient) -> list[Entry]:
        response = await client.get(self._url)
        body = self._parse(response)
        if body.get("errors"):
            log.warning("NextDNS GET returned errors: %s", _error_codes(body))
            raise _Failure(Outcome.UNEXPECTED)
        data = body.get("data")
        if not isinstance(data, list):
            log.warning("NextDNS GET returned an unexpected payload shape")
            raise _Failure(Outcome.UNEXPECTED)
        entries = []
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                entries.append(Entry(item["id"].lower().rstrip("."), item.get("active", True) is not False))
        return entries

    async def _find(self, client: httpx.AsyncClient, hostname: str) -> bool | None:
        """Return None if absent, otherwise the entry's ``active`` flag."""
        for entry in await self._fetch(client):
            if entry.hostname == hostname:
                return entry.active
        return None

    async def _post(self, client: httpx.AsyncClient, hostname: str) -> Outcome:
        response = await client.post(self._url, json={"id": hostname, "active": True})
        if response.status_code == 409:
            return Outcome.ALREADY_PRESENT
        body = self._parse(response, allow_empty=True)
        errors = body.get("errors")
        if errors:
            codes = _error_codes(body)
            log.info("NextDNS POST returned errors: %s", codes)
            if any(hint in code for code in codes for hint in _DUPLICATE_HINTS):
                return Outcome.ALREADY_PRESENT
            return Outcome.REJECTED
        return Outcome.ADDED

    @staticmethod
    def _parse(response: httpx.Response, allow_empty: bool = False) -> dict:
        status = response.status_code
        if status in (401, 403):
            raise _Failure(Outcome.AUTH_FAILED)
        if status == 404:
            raise _Failure(Outcome.PROFILE_NOT_FOUND)
        if status == 429:
            raise _Failure(Outcome.RATE_LIMITED)
        if status >= 500:
            log.warning("NextDNS returned HTTP %d", status)
            raise _Failure(Outcome.UPSTREAM_ERROR)
        if status not in (200, 201, 204, 400):
            log.warning("NextDNS returned unexpected HTTP %d", status)
            raise _Failure(Outcome.UNEXPECTED)
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise _Failure(Outcome.UNEXPECTED)
        if not response.content.strip():
            if allow_empty and status in (200, 201, 204):
                return {}
            raise _Failure(Outcome.UNEXPECTED)
        try:
            body = response.json()
        except ValueError:
            raise _Failure(Outcome.UNEXPECTED) from None
        if not isinstance(body, dict):
            raise _Failure(Outcome.UNEXPECTED)
        if status == 400 and not body.get("errors"):
            raise _Failure(Outcome.UNEXPECTED)
        return body


def _error_codes(body: dict) -> list[str]:
    codes = []
    for err in body.get("errors") or []:
        if isinstance(err, dict):
            codes.append(str(err.get("code", "unknown"))[:40].lower())
    return codes or ["unknown"]
