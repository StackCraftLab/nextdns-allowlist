"""FastAPI application: login, logout, a read-only allowlist view, and a single add operation."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import security
from .config import Settings, load_settings
from .db import Database, Session
from .hostname import InvalidHostname, normalize_hostname
from .nextdns import NextDNSClient

BASE_DIR = Path(__file__).resolve().parent
MAX_FORM_BYTES = 4096
LOGIN_CSRF_PURPOSE = "login-csrf"

log = logging.getLogger("app")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class FormError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail


async def read_form(request: Request) -> dict[str, str]:
    """Parse a small urlencoded form with a hard size limit (no multipart support needed)."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise FormError(415, "Unsupported content type.")
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_FORM_BYTES):
        raise FormError(413, "Request too large.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_FORM_BYTES:
            raise FormError(413, "Request too large.")
    try:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False, max_num_fields=10)
    except (UnicodeDecodeError, ValueError):
        raise FormError(400, "Malformed request.") from None
    # Reject repeated fields instead of guessing which one to use.
    if any(len(v) != 1 for v in parsed.values()):
        raise FormError(400, "Malformed request.")
    return {k: v[0] for k, v in parsed.items()}


def configure_logging() -> None:
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        log.addHandler(handler)  # "app.nextdns" propagates to this logger
        log.setLevel(logging.INFO)
    # httpx logs every request URL at INFO; keep it quiet (it never logs headers/API key).
    logging.getLogger("httpx").setLevel(logging.WARNING)


def create_app(settings: Settings | None = None, nextdns: NextDNSClient | None = None) -> FastAPI:
    configure_logging()
    settings = settings or load_settings()
    db = Database(settings.database_path)
    db.init()
    nextdns = nextdns or NextDNSClient(settings.nextdns_api_key, settings.nextdns_profile_id)
    templates = Jinja2Templates(directory=BASE_DIR / "templates")  # autoescape on for .html
    idle_seconds = settings.session_idle_minutes * 60
    absolute_seconds = settings.session_absolute_hours * 3600

    login_ip_limiter = security.SlidingWindowLimiter(limit=10, window=15 * 60, lockout=15 * 60)
    login_user_limiter = security.SlidingWindowLimiter(limit=20, window=15 * 60, lockout=15 * 60)
    add_limiter = security.SlidingWindowLimiter(limit=30, window=60, lockout=60)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = db
    app.state.nextdns = nextdns
    app.state.limiters = (login_ip_limiter, login_user_limiter, add_limiter)

    # Render provides RENDER_EXTERNAL_HOSTNAME (e.g. myapp.onrender.com) automatically.
    default_hosts = os.environ.get("RENDER_EXTERNAL_HOSTNAME") or "*"
    allowed_hosts = {
        h.strip().lower() for h in (os.environ.get("APP_ALLOWED_HOSTS") or default_hosts).split(",") if h.strip()
    }
    check_host = bool(allowed_hosts) and "*" not in allowed_hosts

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Host allowlist. /healthz is exempt so platform health checks (Docker, Render)
        # work whatever Host header they send; it discloses nothing.
        if check_host and request.url.path != "/healthz":
            host = request.headers.get("host", "").rsplit(":", 1)[0].lower()
            if host not in allowed_hosts:
                return Response("Invalid host header", status_code=400, media_type="text/plain")
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    templates.env.filters["ts"] = lambda v: datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- helpers -------------------------------------------------------------
    def admin_password_hash(username: str) -> str | None:
        """APP_ADMIN_PASSWORD_HASH (for hosts without persistent disk) wins over the DB."""
        if username != settings.app_username:
            return None
        return settings.admin_password_hash or db.get_password_hash(username)

    def client_ip(request: Request) -> str:
        # request.client reflects X-Forwarded-For only for proxies trusted via
        # uvicorn's --forwarded-allow-ips, so it cannot be spoofed by clients.
        return request.client.host if request.client else "unknown"

    def current_session(request: Request) -> Session | None:
        token = request.cookies.get(settings.session_cookie_name)
        if not token or len(token) > 128:
            return None
        token_hash = security.token_digest(settings.secret_key, token)
        session = db.get_session(token_hash)
        if session is None:
            return None
        now = int(time.time())
        if (
            now - session.last_seen > idle_seconds
            or now - session.created_at > absolute_seconds
            or session.username != settings.app_username
        ):
            db.delete_session(token_hash)
            return None
        if now - session.last_seen > 60:
            db.touch_session(token_hash)
        return session

    def set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            settings.session_cookie_name,
            token,
            max_age=absolute_seconds,
            path="/",
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )

    def clear_session_cookie(response: Response) -> None:
        response.delete_cookie(
            settings.session_cookie_name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
        )

    def redirect(path: str) -> RedirectResponse:
        # Only fixed, internal paths are ever used as redirect targets (no open redirects).
        if path not in {"/", "/login"}:
            raise ValueError("unexpected redirect target")
        return RedirectResponse(path, status_code=303)

    def render_login(request: Request, status: int = 200, error: str | None = None) -> HTMLResponse:
        csrf = security.sign(settings.secret_key, security.new_token(), LOGIN_CSRF_PURPOSE)
        response = templates.TemplateResponse(
            request,
            "login.html",
            {"csrf_token": csrf, "error": error, "configured": admin_password_hash(settings.app_username) is not None},
            status_code=status,
        )
        response.set_cookie(
            settings.login_csrf_cookie_name,
            csrf,
            max_age=3600,
            path="/",
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )
        return response

    def error_page(request: Request, status: int, message: str) -> HTMLResponse:
        return templates.TemplateResponse(request, "error.html", {"message": message}, status_code=status)

    # --- error handling --------------------------------------------------------
    @app.exception_handler(FormError)
    async def form_error_handler(request: Request, exc: FormError):
        return error_page(request, exc.status, exc.detail)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException):
        messages = {404: "Page not found.", 405: "Method not allowed."}
        response = error_page(request, exc.status_code, messages.get(exc.status_code, "Request failed."))
        if exc.headers:
            response.headers.update(exc.headers)
        return response

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        log.error("Unhandled error on %s %s: %s", request.method, request.url.path, type(exc).__name__)
        return error_page(request, 500, "An internal error occurred.")

    # --- routes ----------------------------------------------------------------
    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return JSONResponse({"status": "ok"})

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if current_session(request):
            return redirect("/")
        return render_login(request)

    @app.post("/login")
    async def login(request: Request):
        form = await read_form(request)
        cookie_token = request.cookies.get(settings.login_csrf_cookie_name)
        form_token = form.get("csrf_token", "")
        if not (
            security.tokens_equal(cookie_token, form_token)
            and security.verify_signed(settings.secret_key, form_token, LOGIN_CSRF_PURPOSE)
        ):
            return render_login(request, 403, "Your session expired. Please try again.")

        ip = client_ip(request)
        username = form.get("username", "")[:64]
        password = form.get("password", "")
        wait = max(login_ip_limiter.retry_after(ip), login_user_limiter.retry_after(username.lower()))
        if wait:
            log.warning("Login blocked by rate limit from %s", ip)
            response = render_login(request, 429, f"Too many failed attempts. Try again in {wait // 60 + 1} minutes.")
            response.headers["Retry-After"] = str(wait)
            return response

        stored = admin_password_hash(username)
        if not security.verify_password(stored, password):
            login_ip_limiter.hit(ip)
            login_user_limiter.hit(username.lower())
            log.warning("Failed login from %s", ip)
            return render_login(request, 401, "Invalid username or password.")

        if not settings.admin_password_hash and security.password_hasher.check_needs_rehash(stored):
            db.set_password_hash(username, security.password_hasher.hash(password))
        login_ip_limiter.reset(ip)
        login_user_limiter.reset(username.lower())
        db.purge_expired_sessions(idle_seconds, absolute_seconds)

        # Always issue a brand-new session token (prevents session fixation).
        token = security.new_token()
        db.create_session(security.token_digest(settings.secret_key, token), username, security.new_token())
        log.info("Successful login from %s", ip)
        response = redirect("/")
        set_session_cookie(response, token)
        response.delete_cookie(settings.login_csrf_cookie_name, path="/", secure=settings.cookie_secure)
        return response

    @app.post("/logout")
    async def logout(request: Request):
        session = current_session(request)
        if session is None:
            response = redirect("/login")
            clear_session_cookie(response)
            return response
        form = await read_form(request)
        if not security.tokens_equal(form.get("csrf_token"), session.csrf_token):
            return error_page(request, 403, "Invalid or missing CSRF token.")
        db.delete_session(session.token_hash)
        response = redirect("/login")
        clear_session_cookie(response)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        session = current_session(request)
        if session is None:
            return redirect("/login")
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "csrf_token": session.csrf_token,
                "username": session.username,
                "flash": db.pop_flash(session.token_hash),
                "recent": db.recent_submissions(),
                "profile_id": settings.nextdns_profile_id,
            },
        )

    @app.get("/allowlist", response_class=HTMLResponse)
    async def allowlist(request: Request, q: str = ""):
        """Read-only view of the profile's current allowlist."""
        session = current_session(request)
        if session is None:
            return redirect("/login")
        query = q.strip().lower()[:255]
        result = await nextdns.list_entries()
        entries = sorted(result.entries, key=lambda e: e.hostname)
        total = len(entries)
        if query:
            entries = [e for e in entries if query in e.hostname]
        return templates.TemplateResponse(
            request,
            "allowlist.html",
            {
                "csrf_token": session.csrf_token,
                "username": session.username,
                "profile_id": settings.nextdns_profile_id,
                "entries": entries,
                "total": total,
                "query": query,
                "error": None if result.outcome.ok else result.message,
            },
        )

    @app.post("/add")
    async def add(request: Request):
        """The single state-changing NextDNS operation this application exposes."""
        session = current_session(request)
        if session is None:
            return error_page(request, 401, "You must be logged in.")
        form = await read_form(request)
        if not security.tokens_equal(form.get("csrf_token"), session.csrf_token):
            return error_page(request, 403, "Invalid or missing CSRF token.")

        if add_limiter.retry_after(session.username):
            db.set_flash(session.token_hash, "error", "Too many submissions. Please wait a minute.")
            return redirect("/")
        add_limiter.hit(session.username)

        try:
            hostname = normalize_hostname(form.get("hostname", ""))
        except InvalidHostname as exc:
            db.set_flash(session.token_hash, "error", str(exc))
            return redirect("/")

        result = await nextdns.add(hostname)
        db.record_submission(session.username, hostname, result.outcome.value)
        log.info("Allowlist add %s -> %s", hostname, result.outcome.value)
        db.set_flash(session.token_hash, "success" if result.outcome.ok else "error", result.message)
        return redirect("/")

    return app
