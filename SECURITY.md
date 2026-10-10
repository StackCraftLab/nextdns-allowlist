# Security design note

## Threat model in one paragraph

The application is reachable from the internet. It holds a NextDNS API key that
can control the whole NextDNS account. The goal is that anyone using the web UI,
including a legitimate but careless or compromised admin session, can do exactly
one thing: **append a hostname to the allowlist of one configured profile.**

## How the add-only restriction is enforced (application level)

| Layer | Control |
|---|---|
| HTTP surface | Exactly seven routes: `GET /healthz`, `GET/POST /login`, `POST /logout`, `GET /`, `GET /allowlist` (read-only view), `POST /add`. No PUT/PATCH/DELETE routes, no generic proxy, no API docs. A test asserts the route table is exactly this set. |
| Input | `/add` reads one field, `hostname`, and validates it strictly. Extra fields (`url`, `method`, ...) are ignored. There's no way to supply a URL, path, method or profile. |
| Outbound URL | `https://api.nextdns.io/profiles/<PROFILE_ID>/allowlist` is built from a constant plus a profile ID validated as `[A-Za-z0-9]{1,32}` at startup. Redirects are not followed. |
| Outbound methods | `NextDNSClient` calls only `client.get()` (duplicate check and the read-only list view) and `client.post()` with body `{"id": host, "active": true}`. There's no code path for PUT (which would **replace the whole array**), PATCH (edit) or DELETE. A static AST test fails the build if any `put/patch/delete/request/send/stream` call or a `"PUT"/"PATCH"/"DELETE"` string appears in `app/`. |
| Duplicates | Before posting, the app reads the allowlist. If the host is present it reports that and changes **nothing**. If it's present but disabled, the app does *not* PATCH it to enabled; it tells the user to ask an administrator. Updates are never used as a fallback for adds. |
| Re-validation | The client rejects any hostname that isn't already in normalised form (defence in depth). |

## API-key limitation (important)

**NextDNS doesn't offer scoped or restricted API keys.** The official API docs
(<https://nextdns.github.io/api/>) describe a single, account-wide key from the
account page, sent as `X-Api-Key`. There's no way to issue a key limited to one
profile, to the allowlist, or to POST only.

So:

* The add-only guarantee is enforced **only by this application's code**. It does
  **not** restrict the API key itself.
* Anyone who obtains the key (server compromise, leaked `.env`, backup, memory
  dump) can read, change or delete **every profile and setting** in the
  NextDNS account, including deleting allowlist entries or replacing the
  allowlist with `PUT`.

Mitigations you should apply:

1. **Use a dedicated NextDNS account** that owns only this profile, so a leaked
   key can't affect other profiles. If NextDNS later adds profile-scoped or
   read/write-scoped keys, switch to one.
2. Keep `.env` (or the Docker secret files) at `chmod 600`, owned by the deploy
   user, excluded from git and backups that leave the host.
3. Rotate the key in the NextDNS account page if compromise is suspected, then
   update `.env` and run `docker compose up -d`.
4. Keep the container read-only and non-root (as configured in `compose.yaml`).

## Other notes on API behaviour

* User errors may come back as **HTTP 200 or 400** with `{"errors": [...]}`, so
  the client never treats a 2xx status alone as success.
* Verified against the live API: an invalid or missing key returns
  `HTTP 403 {"errors":[{"code":"authRequired"}]}`.
* The response to POSTing a duplicate is **undocumented**, so the app avoids the
  question by checking with GET first. If a duplicate still reaches the API (a
  race), an `errors` code containing `duplicate`, `exist`, `already` or
  `conflict`, or HTTP 409, is reported as "already present". Any other error is
  reported as "rejected" and never as success.
* 404 → profile not found, 429 → rate limited, 5xx → temporarily unavailable,
  network errors and timeouts (10 s) → "could not reach NextDNS". Upstream
  bodies are never shown to the user.
* The API is labelled beta by NextDNS; the behaviour above may change.
* Not verified live: a successful POST, because that needs a real key and would
  change your profile. Test it once yourself after deployment (see the README).

## Authentication and session controls

* Single admin user. Password hashed with **Argon2id** (argon2-cffi defaults,
  t=3, m=64 MiB, p=4), set only through `python -m app.manage set-password`.
  There are no default credentials, no registration and no password reset. Changing
  the password revokes all sessions.
* Alternatively (for hosts without persistent storage such as Render's free plan)
  the hash can be supplied via `APP_ADMIN_PASSWORD_HASH`, generated with
  `python -m app.manage hash-password`. Only Argon2id hashes are accepted, so a
  plaintext password is never placed in the environment. It overrides the DB value.
* Server-side sessions in SQLite. The cookie holds a 256-bit random token; the DB
  stores only `HMAC-SHA256(APP_SECRET_KEY, token)`. A new token is issued on every
  login (no fixation). Idle timeout is 30 min and the absolute lifetime is 12 h,
  both configurable.
* Cookie: `__Host-session; Secure; HttpOnly; SameSite=Strict; Path=/`. In
  `APP_ENV=production` Secure is always on and can't be disabled.
* CSRF: a per-session random token is required on `/add` and `/logout`. The login
  form uses an HMAC-signed double-submit token in a `__Host-` cookie. SameSite=Strict
  adds a second layer.
* Brute force: 10 failed logins per IP or 20 per username within 15 minutes →
  15-minute lockout (HTTP 429). Unknown usernames still cost one Argon2 run
  (no user enumeration through timing). At most 2 concurrent Argon2 verifications.
  Counters live in memory and reset when the container restarts, which is why the
  app runs as exactly one worker.
  Trade-off: the per-username limit lets an attacker temporarily lock the admin
  out. The per-IP limit applies first; the admin can restart the container to clear it.
* Client IP comes from `X-Forwarded-For` only when the request comes from an
  address in `FORWARDED_ALLOW_IPS` (the reverse proxy).

## Web hardening

* Strict CSP (`default-src 'none'`, no scripts at all), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, HSTS in production, `Cache-Control: no-store`.
* Jinja2 autoescaping for all output. Form bodies are capped at 4 KB, must be
  `application/x-www-form-urlencoded`, and repeated fields are rejected.
* Redirects only go to the fixed paths `/` and `/login` (no `next=` parameter).
* Optional `Host` header allowlist via `APP_ALLOWED_HOSTS`.
* Errors render a generic page. Stack traces are never sent to the browser.
* Logs contain IP addresses, hostnames and outcome codes. They never contain the API key,
  passwords, session tokens or upstream response bodies (tested).
* `/add` is limited to 30 submissions per minute per user to protect the NextDNS
  rate limit.

## Render.com specifics

* The free plan has no persistent disk, so sessions, recent submissions and login
  rate-limit counters reset whenever the instance sleeps (~15 min idle) or redeploys.
  The lockout therefore slows brute-force attacks but can't stop them over long
  periods; a long random password is essential.
* `NEXTDNS_API_KEY` and `APP_ADMIN_PASSWORD_HASH` are entered in the Render dashboard
  (`sync: false`) and never committed. Anyone with access to your Render account can
  read them, so protect it with 2FA.
* `FORWARDED_ALLOW_IPS=*` is safe there only because the container has no public
  address of its own; don't copy that setting to a host where port 8000 is exposed.

## Hostname policy

Bare hostnames only: at least two labels, each 1-63 characters of `[a-z0-9-]` with no
leading or trailing hyphen, 253 characters maximum, lower-cased, with one trailing dot removed.
Schemes, paths, queries, fragments, ports, userinfo, whitespace, wildcards and IP
literals are rejected. **IDNs are accepted only in ASCII/punycode (`xn--`) form.**
Unicode input is rejected to avoid IDNA2003/2008 ambiguity and homograph confusion.
