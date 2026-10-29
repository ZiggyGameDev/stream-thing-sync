"""stream-thing-sync: accounts, encrypted API keys and watch progress for stream-thing.

One file on purpose: a FastAPI app over a single SQLite database. See README.md
for the API contract. Secrets (SECRET_KEY, GOOGLE_DESKTOP_CLIENT_SECRET) come
from the environment only.

Nothing secret is ever logged: not device tokens, session ids, Google ID
tokens, OAuth codes/verifiers or API keys. uvicorn's access log is turned off
(it would print query strings); the middleware below logs paths only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("stream_thing_sync")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)

# --- constants ---------------------------------------------------------------

SESSION_COOKIE = "sts_session"
SESSION_TTL_S = 60 * 24 * 3600
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "sync"
CREDENTIAL_KEYS = ("debrid_service", "torbox", "realdebrid", "mdblist", "poster")
DEBRID_SERVICES = ("torbox", "realdebrid")
MAX_CREDENTIAL_LEN = 512
MAX_PROGRESS_ENTRIES = 500
MAX_DEVICE_NAME_LEN = 80
MAX_BODY_BYTES = 1_000_000
MAX_NUMBER = 1e10
LAST_USED_RESOLUTION_MS = 60_000
VIDEO_ID_RE = re.compile(r"^[\x21-\x7e]{1,200}$")  # printable ASCII, no spaces
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
SCHEMA_VERSION = 2
STATIC_DIR = Path(__file__).resolve().parent / "static"

# App updates: $DATA_DIR/updates holds latest.json and the files it points at. Published by
# stream-thing's scripts/publish-update.mjs over scp; this server only reads them.
UPDATE_FILE_TYPES = {
    ".apk": "application/vnd.android.package-archive",
    ".exe": "application/octet-stream",
}
UPDATE_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def now_ms() -> int:
    """Wall clock in ms. Module-level so tests can monkeypatch it."""
    return int(time.time() * 1000)


def monotonic() -> float:
    return time.monotonic()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --- Google ------------------------------------------------------------------


def verify_google_token(credential: str, audience: str | list[str]) -> dict:
    """Verify a Google ID token against one client ID or a list of them.

    Raises ValueError / GoogleAuthError when invalid. Tests monkeypatch this."""
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    return id_token.verify_oauth2_token(credential, google_requests.Request(), audience)


class GoogleCodeRejected(Exception):
    """Google refused the authorization code (bad, expired, reused, wrong verifier...)."""


class GoogleUnavailable(Exception):
    """Couldn't reach Google, or it refused our client configuration."""


def exchange_google_code(code: str, code_verifier: str, redirect_uri: str,
                         client_id: str, client_secret: str) -> dict:
    """Exchange an authorization code (PKCE) at Google's token endpoint and return
    its JSON response, which carries `id_token`. Tests monkeypatch this."""
    import requests

    try:
        r = requests.post(GOOGLE_TOKEN_URL, timeout=10, data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        })
    except requests.RequestException as exc:
        raise GoogleUnavailable(type(exc).__name__) from None
    if r.status_code in (400, 401):
        try:
            error = str(r.json().get("error", "invalid_grant"))
        except ValueError:
            error = "invalid_grant"
        if error in ("invalid_client", "unauthorized_client"):
            raise GoogleUnavailable(f"token endpoint rejected the client: {error}")
        raise GoogleCodeRejected(error)
    if r.status_code != 200:
        raise GoogleUnavailable(f"token endpoint returned {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise GoogleUnavailable("token endpoint returned non-JSON") from None


def valid_loopback_redirect(uri) -> bool:
    """Only http://127.0.0.1:<port>/... or http://localhost:<port>/... (desktop loopback flow)."""
    if not isinstance(uri, str) or len(uri) > 512:
        return False
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "http"
            and port is not None and 0 < port < 65536
            and parts.netloc.lower() in (f"127.0.0.1:{port}", f"localhost:{port}")
            and (parts.path == "" or parts.path.startswith("/"))
            and not parts.fragment)


# --- settings ----------------------------------------------------------------


def _split_ids(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in value.split(",") if x.strip())


@dataclass
class Settings:
    google_client_id: str  # the web client: website sign-in, and always an accepted app audience
    secret_key: str
    public_url: str
    data_dir: str
    # Extra audiences accepted by POST /api/auth/google.
    google_client_ids: tuple[str, ...] = ()
    desktop_client_id: str = ""
    desktop_client_secret: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        missing = [k for k in ("GOOGLE_CLIENT_ID", "SECRET_KEY") if not os.environ.get(k, "").strip()]
        if missing:
            raise RuntimeError(f"missing required environment variable(s): {', '.join(missing)} (see .env.example)")
        return cls(
            google_client_id=os.environ["GOOGLE_CLIENT_ID"].strip(),
            secret_key=os.environ["SECRET_KEY"].strip(),
            public_url=os.environ.get("PUBLIC_URL", "https://sync.thestoreisclosed.co.uk").strip().rstrip("/"),
            data_dir=os.environ.get("DATA_DIR", "/data").strip(),
            google_client_ids=_split_ids(os.environ.get("GOOGLE_CLIENT_IDS", "")),
            desktop_client_id=os.environ.get("GOOGLE_DESKTOP_CLIENT_ID", "").strip(),
            desktop_client_secret=os.environ.get("GOOGLE_DESKTOP_CLIENT_SECRET", "").strip(),
        )

    @property
    def app_audiences(self) -> list[str]:
        return list(dict.fromkeys((self.google_client_id,) + tuple(self.google_client_ids)))

    @property
    def secure_cookies(self) -> bool:
        return self.public_url.startswith("https://")


# --- errors ------------------------------------------------------------------


class ApiError(Exception):
    def __init__(self, status: int, error: str):
        super().__init__(error)
        self.status = status
        self.error = error


# --- database ----------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    google_sub    TEXT NOT NULL UNIQUE,
    email         TEXT,
    name          TEXT,
    picture       TEXT,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
CREATE TABLE IF NOT EXISTS credentials (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    blob       BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS progress (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    video_id   TEXT NOT NULL,
    position   REAL,
    duration   REAL,
    watched    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,  -- the device's clock: decides which write wins
    changed_at INTEGER NOT NULL,  -- the server's clock: what `since` filters on
    PRIMARY KEY (user_id, video_id)
);
CREATE INDEX IF NOT EXISTS progress_since ON progress(user_id, changed_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current = row[0] or 0
            if current < 2:
                # v2: the device-code sign-in flow was removed.
                c.execute("DROP TABLE IF EXISTS link_requests")
            if current < SCHEMA_VERSION:
                c.execute("DELETE FROM schema_version")
                c.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


# --- rate limiting -----------------------------------------------------------


class TokenBucket:
    """Per-key token bucket: `capacity` burst, refilled at capacity/per_seconds."""

    def __init__(self, capacity: float, per_seconds: float):
        self.capacity = capacity
        self.rate = capacity / per_seconds
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        t = monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.capacity, t))
            tokens = min(self.capacity, tokens + (t - last) * self.rate)
            ok = tokens >= 1
            self.buckets[key] = (tokens - 1 if ok else tokens, t)
            if len(self.buckets) > 20_000:
                full = [k for k, (tk, lt) in self.buckets.items() if tk + (t - lt) * self.rate >= self.capacity]
                for k in full:
                    del self.buckets[k]
            return ok


def client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip", "").strip()
    if cf:
        return cf
    return request.client.host if request.client else "unknown"


# --- helpers -----------------------------------------------------------------


async def read_json(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise ApiError(413, "request too large")
    if not raw:
        raise ApiError(400, "expected a JSON object body")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "invalid JSON")
    if not isinstance(data, dict):
        raise ApiError(400, "expected a JSON object body")
    return data


def device_name_from(body: dict) -> str:
    name = body.get("device_name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError(400, "device_name is required")
    return " ".join(name.split())[:MAX_DEVICE_NAME_LEN]


def check_number(value, what: str):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError(400, f"{what} must be a number or null")
    if not math.isfinite(value) or value < 0 or value > MAX_NUMBER:
        raise ApiError(400, f"{what} out of range")
    return float(value)


# --- app ---------------------------------------------------------------------


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    try:
        fernet = Fernet(settings.secret_key.encode())
    except (ValueError, TypeError):
        raise RuntimeError("SECRET_KEY must be a urlsafe base64 32-byte Fernet key (see .env.example)")
    session_key = hashlib.sha256(b"stream-thing-sync/session/" + settings.secret_key.encode()).digest()
    db = Database(Path(settings.data_dir) / "sync.db")
    page_template = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    # A JS string literal that can't close the <script> element.
    client_id_json = json.dumps(settings.google_client_id).replace("<", "\\u003c").replace(">", "\\u003e")

    app = FastAPI(title="stream-thing-sync", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = db
    login_limiter = TokenBucket(capacity=10, per_seconds=60)     # website sign-in, per IP
    app_auth_limiter = TokenBucket(capacity=10, per_seconds=60)  # in-app sign-in, per IP

    def session_hash(token: str) -> str:
        return hmac.new(session_key, token.encode(), hashlib.sha256).hexdigest()

    # --- error handling / middleware ---

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return JSONResponse({"error": exc.error}, status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        message = {404: "not found", 405: "method not allowed"}.get(exc.status_code, str(exc.detail))
        return JSONResponse({"error": message}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"error": "internal error"}, status_code=500)

    @app.middleware("http")
    async def _headers_and_log(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path != "/healthz":
            # Path only, never query strings.
            log.info("%s %s %s %.0fms", request.method, request.url.path, response.status_code,
                     (time.perf_counter() - start) * 1000)
        return response

    # --- auth ---

    def device_auth(conn: sqlite3.Connection, request: Request) -> sqlite3.Row:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise ApiError(401, "missing or invalid token")
        row = conn.execute(
            """SELECT d.id AS device_id, d.name AS device_name, d.last_used_at AS device_last_used,
                      u.id AS user_id, u.email, u.name
               FROM devices d JOIN users u ON u.id = d.user_id WHERE d.token_hash = ?""",
            (sha256_hex(token),),
        ).fetchone()
        if row is None:
            raise ApiError(401, "missing or invalid token")
        t = now_ms()
        if t - row["device_last_used"] >= LAST_USED_RESOLUTION_MS:
            conn.execute("UPDATE devices SET last_used_at = ? WHERE id = ?", (t, row["device_id"]))
        return row

    def web_auth(conn: sqlite3.Connection, request: Request) -> sqlite3.Row:
        if request.method not in ("GET", "HEAD") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise ApiError(403, "missing X-Requested-With header")
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            raise ApiError(401, "not signed in")
        t = now_ms()
        row = conn.execute(
            """SELECT s.id_hash, s.last_used_at AS session_last_used, u.*
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.id_hash = ? AND s.expires_at > ?""",
            (session_hash(token), t),
        ).fetchone()
        if row is None:
            raise ApiError(401, "not signed in")
        if t - row["session_last_used"] >= LAST_USED_RESOLUTION_MS:
            conn.execute("UPDATE sessions SET last_used_at = ? WHERE id_hash = ?", (t, row["id_hash"]))
        return row

    def require_csrf(request: Request):
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise ApiError(403, "missing X-Requested-With header")

    async def verify_identity(credential, audience) -> dict:
        """Verify a Google ID token in a worker thread; map failures to API errors."""
        from google.auth.exceptions import GoogleAuthError, TransportError

        if not isinstance(credential, str) or not credential or len(credential) > 8192:
            raise ApiError(400, "a Google ID token is required")
        try:
            info = await run_in_threadpool(verify_google_token, credential, audience)
        except TransportError:
            log.warning("could not reach Google to verify a sign-in")
            raise ApiError(502, "could not reach Google, try again")
        except (ValueError, GoogleAuthError):
            raise ApiError(401, "invalid Google credential")
        if not info.get("sub"):
            raise ApiError(401, "invalid Google credential")
        return info

    def upsert_user(conn, info: dict) -> int:
        """Sign-in is sign-up: the first time a Google `sub` is seen, the user is created."""
        t = now_ms()
        conn.execute(
            """INSERT INTO users (google_sub, email, name, picture, created_at, last_login_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email, name = excluded.name,
                   picture = excluded.picture, last_login_at = excluded.last_login_at""",
            (info["sub"], info.get("email"), info.get("name"), info.get("picture"), t, t),
        )
        return conn.execute("SELECT id FROM users WHERE google_sub = ?", (info["sub"],)).fetchone()["id"]

    def sign_in_device(info: dict, device_name: str) -> dict:
        token = secrets.token_urlsafe(32)
        t = now_ms()
        with db.connect() as conn:
            user_id = upsert_user(conn, info)
            conn.execute(
                """INSERT INTO devices (id, user_id, name, token_hash, created_at, last_used_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (secrets.token_hex(8), user_id, device_name, sha256_hex(token), t, t),
            )
        log.info("device signed in for user %s", user_id)
        return {"token": token, "account": {"email": info.get("email"), "name": info.get("name")}}

    # --- shared operations ---

    def load_credentials(conn, user_id: int) -> dict:
        row = conn.execute("SELECT blob, updated_at FROM credentials WHERE user_id = ?", (user_id,)).fetchone()
        if row is None:
            return {"credentials": {}, "updated_at": None}
        try:
            creds = json.loads(fernet.decrypt(bytes(row["blob"])))
        except InvalidToken:
            log.error("credentials for user %s could not be decrypted (SECRET_KEY changed?)", user_id)
            raise ApiError(500, "stored credentials could not be decrypted")
        return {"credentials": {k: v for k, v in creds.items() if k in CREDENTIAL_KEYS and v},
                "updated_at": int(row["updated_at"])}

    def put_credentials(conn, user_id: int, body: dict) -> dict:
        incoming = body.get("credentials")
        if not isinstance(incoming, dict):
            raise ApiError(400, "expected {\"credentials\": {...}}")
        changes: dict[str, str | None] = {}
        for key, value in incoming.items():
            if key not in CREDENTIAL_KEYS:
                raise ApiError(400, f"unknown credential key (allowed: {', '.join(CREDENTIAL_KEYS)})")
            if value is None or value == "":
                changes[key] = None
            elif isinstance(value, str):
                value = value.strip()
                if len(value) > MAX_CREDENTIAL_LEN:
                    raise ApiError(400, f"{key} is longer than {MAX_CREDENTIAL_LEN} characters")
                changes[key] = value or None
            else:
                raise ApiError(400, f"{key} must be a string or null")
            if key == "debrid_service" and changes[key] is not None and changes[key] not in DEBRID_SERVICES:
                raise ApiError(400, f"debrid_service must be one of: {', '.join(DEBRID_SERVICES)}")
        current = load_credentials(conn, user_id)["credentials"]
        for key, value in changes.items():
            if value is None:
                current.pop(key, None)
            else:
                current[key] = value
        blob = fernet.encrypt(json.dumps(current).encode())
        conn.execute(
            """INSERT INTO credentials (user_id, blob, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at""",
            (user_id, blob, now_ms()),
        )
        return load_credentials(conn, user_id)

    def list_devices(conn, user_id: int) -> list[dict]:
        rows = conn.execute(
            "SELECT id, name, created_at, last_used_at FROM devices WHERE user_id = ? ORDER BY last_used_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- pages ---

    def render_page() -> HTMLResponse:
        nonce = secrets.token_urlsafe(16)
        body = page_template.replace("{{CLIENT_ID_JSON}}", client_id_json).replace("{{NONCE}}", nonce)
        csp = "; ".join([
            "default-src 'self'",
            f"script-src 'nonce-{nonce}' https://accounts.google.com/gsi/client",
            "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style",
            "frame-src https://accounts.google.com/gsi/",
            "connect-src 'self' https://accounts.google.com/gsi/",
            "img-src 'self' data: https://*.googleusercontent.com",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ])
        return HTMLResponse(body, headers={
            "Content-Security-Policy": csp,
            # GIS popup mode needs to talk back to this window.
            "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
            "Cache-Control": "no-store",
        })

    @app.get("/", include_in_schema=False)
    async def index_page():
        return render_page()

    legal_template = (STATIC_DIR / "legal.html").read_text(encoding="utf-8")
    legal_pages = {
        name: legal_template.replace("{{TITLE}}", title)
                            .replace("{{BODY}}", (STATIC_DIR / f"{name}.html").read_text(encoding="utf-8"))
        for name, title in (("privacy", "Privacy"), ("terms", "Terms"))
    }
    legal_headers = {
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                                   "form-action 'none'; frame-ancestors 'none'",
        "Cache-Control": "public, max-age=3600",
    }

    @app.get("/privacy", include_in_schema=False)
    async def privacy_page():
        return HTMLResponse(legal_pages["privacy"], headers=legal_headers)

    @app.get("/terms", include_in_schema=False)
    async def terms_page():
        return HTMLResponse(legal_pages["terms"], headers=legal_headers)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    # --- app updates (public, read-only) ---

    updates_dir = Path(settings.data_dir) / "updates"
    # Always revalidated: a re-published build under the same name must never be served
    # stale by the tunnel's edge, or the app's sha256 check fails.
    no_cache = {"Cache-Control": "no-cache"}

    @app.api_route("/updates/latest.json", methods=["GET", "HEAD"], include_in_schema=False)
    async def update_manifest():
        path = updates_dir / "latest.json"
        try:
            raw = await run_in_threadpool(path.read_bytes)
        except (FileNotFoundError, NotADirectoryError):
            raise ApiError(404, "no update published")
        try:
            json.loads(raw)
        except ValueError:
            log.error("updates/latest.json is not valid JSON")
            raise ApiError(503, "update manifest unreadable")
        return Response(raw, media_type="application/json", headers=no_cache)

    @app.api_route("/updates/files/{name}", methods=["GET", "HEAD"], include_in_schema=False)
    async def update_file(name: str):
        media_type = UPDATE_FILE_TYPES.get(Path(name).suffix.lower())
        if not media_type or not UPDATE_FILE_NAME.match(name) or ".." in name:
            raise ApiError(404, "not found")
        path = updates_dir / name
        # Belt and braces: the pattern already rules out separators.
        if path.resolve().parent != updates_dir.resolve() or not path.is_file():
            raise ApiError(404, "not found")
        # FileResponse streams from disk and answers Range requests.
        return FileResponse(path, media_type=media_type, filename=name, headers=no_cache,
                            content_disposition_type="attachment")

    # --- in-app sign-in (returns a device token) ---

    @app.post("/api/auth/google")
    async def auth_google(request: Request):
        """Android: Credential Manager gives the app an ID token whose audience is the
        web client ID; any ID listed in GOOGLE_CLIENT_IDS is accepted too."""
        if not app_auth_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many requests")
        body = await read_json(request)
        name = device_name_from(body)
        info = await verify_identity(body.get("id_token"), settings.app_audiences)
        return sign_in_device(info, name)

    @app.post("/api/auth/google-code")
    async def auth_google_code(request: Request):
        """Windows: system-browser loopback flow with PKCE. The app sends the code and
        verifier; the client secret stays on the server. The ID token Google returns
        is then verified against the desktop client ID."""
        if not app_auth_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many requests")
        if not (settings.desktop_client_id and settings.desktop_client_secret):
            raise ApiError(503, "desktop sign-in is not configured on this server")
        body = await read_json(request)
        name = device_name_from(body)
        code, verifier, redirect_uri = body.get("code"), body.get("code_verifier"), body.get("redirect_uri")
        if not isinstance(code, str) or not code or len(code) > 2048:
            raise ApiError(400, "code is required")
        if not isinstance(verifier, str) or not 43 <= len(verifier) <= 128:  # RFC 7636
            raise ApiError(400, "code_verifier must be 43-128 characters")
        if not valid_loopback_redirect(redirect_uri):
            raise ApiError(400, "redirect_uri must be http://127.0.0.1:<port>/... or http://localhost:<port>/...")
        try:
            tokens = await run_in_threadpool(exchange_google_code, code, verifier, redirect_uri,
                                             settings.desktop_client_id, settings.desktop_client_secret)
        except GoogleCodeRejected:
            raise ApiError(401, "Google rejected the authorization code")
        except GoogleUnavailable as exc:
            log.warning("Google code exchange failed: %s", exc)
            raise ApiError(502, "could not complete sign-in with Google, try again")
        info = await verify_identity(tokens.get("id_token"), settings.desktop_client_id)
        return sign_in_device(info, name)

    # --- device API ---

    @app.get("/api/me")
    async def me(request: Request):
        with db.connect() as conn:
            d = device_auth(conn, request)
        return {"email": d["email"], "name": d["name"], "device": {"id": d["device_id"], "name": d["device_name"]}}

    @app.get("/api/credentials")
    async def device_get_credentials(request: Request):
        with db.connect() as conn:
            d = device_auth(conn, request)
            return load_credentials(conn, d["user_id"])

    @app.put("/api/credentials")
    async def device_put_credentials(request: Request):
        body = await read_json(request)
        with db.connect() as conn:
            d = device_auth(conn, request)
            return put_credentials(conn, d["user_id"], body)

    def sync_watermark() -> int:
        # The `now` handed to clients as their next `since`. One ms behind the
        # clock: a write later in this same millisecond gets changed_at == now_ms(),
        # which `changed_at > since` would otherwise skip. Rows from the previous
        # millisecond may be sent twice, which newest-wins merging makes harmless.
        return now_ms() - 1

    @app.get("/api/progress")
    async def get_progress(request: Request, since: str = "0"):
        try:
            since_ms = int(since)
        except ValueError:
            raise ApiError(400, "since must be an integer (ms epoch)")
        with db.connect() as conn:
            d = device_auth(conn, request)
            watermark = sync_watermark()
            # `since` is the `now` this server handed out earlier, so it is compared
            # with changed_at (the server's clock when the row was last written), never
            # with the device-supplied updatedAt: a device whose clock runs behind
            # must not be able to hide its updates from the others.
            rows = conn.execute(
                """SELECT video_id, position, duration, watched, updated_at FROM progress
                   WHERE user_id = ? AND changed_at > ?""",
                (d["user_id"], since_ms),
            ).fetchall()
        return {
            "progress": {
                r["video_id"]: {"position": r["position"], "duration": r["duration"],
                                "watched": bool(r["watched"]), "updatedAt": int(r["updated_at"])}
                for r in rows
            },
            "now": watermark,
        }

    @app.post("/api/progress")
    async def post_progress(request: Request):
        body = await read_json(request)
        entries = body.get("progress")
        if not isinstance(entries, dict):
            raise ApiError(400, "expected {\"progress\": {...}}")
        if len(entries) > MAX_PROGRESS_ENTRIES:
            raise ApiError(400, f"at most {MAX_PROGRESS_ENTRIES} entries per request")
        t = now_ms()
        rows = []
        for video_id, entry in entries.items():
            if not VIDEO_ID_RE.match(video_id):
                raise ApiError(400, "invalid videoId")
            if not isinstance(entry, dict):
                raise ApiError(400, f"entry for {video_id} must be an object")
            position = check_number(entry.get("position"), "position")
            duration = check_number(entry.get("duration"), "duration")
            watched = entry.get("watched", False)
            if not isinstance(watched, bool):
                raise ApiError(400, "watched must be a boolean")
            updated = entry.get("updatedAt")
            if isinstance(updated, bool) or not isinstance(updated, (int, float)) or not math.isfinite(updated) \
                    or updated <= 0:
                raise ApiError(400, "updatedAt must be a positive ms epoch")
            # A device clock running ahead must not win forever: clamp to server time.
            updated = min(int(updated), t)
            rows.append((video_id, position, duration, int(watched), updated, t))
        with db.connect() as conn:
            d = device_auth(conn, request)
            conn.executemany(
                """INSERT INTO progress (user_id, video_id, position, duration, watched, updated_at, changed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id, video_id) DO UPDATE SET
                       position = excluded.position, duration = excluded.duration, watched = excluded.watched,
                       updated_at = excluded.updated_at, changed_at = excluded.changed_at
                   WHERE excluded.updated_at >= progress.updated_at""",
                [(d["user_id"],) + r for r in rows],
            )
        return {"ok": True, "now": sync_watermark()}

    @app.post("/api/logout")
    async def device_logout(request: Request):
        with db.connect() as conn:
            d = device_auth(conn, request)
            conn.execute("DELETE FROM devices WHERE id = ?", (d["device_id"],))
        return {"ok": True}

    # --- website API (cookie session) ---

    @app.post("/api/web/google")
    async def web_google(request: Request):
        require_csrf(request)
        if not login_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many requests")
        body = await read_json(request)
        info = await verify_identity(body.get("credential"), settings.google_client_id)
        token = secrets.token_urlsafe(32)
        t = now_ms()
        with db.connect() as conn:
            user_id = upsert_user(conn, info)
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (t,))
            conn.execute(
                "INSERT INTO sessions (id_hash, user_id, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
                (session_hash(token), user_id, t, t + SESSION_TTL_S * 1000, t),
            )
        response = JSONResponse({"ok": True, "email": info.get("email"), "name": info.get("name")})
        response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_S, httponly=True,
                            secure=settings.secure_cookies, samesite="lax", path="/")
        return response

    @app.get("/api/web/me")
    async def web_me(request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
        return {"email": u["email"], "name": u["name"], "picture": u["picture"]}

    @app.post("/api/web/logout")
    async def web_logout(request: Request):
        require_csrf(request)
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            with db.connect() as conn:
                conn.execute("DELETE FROM sessions WHERE id_hash = ?", (session_hash(token),))
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.secure_cookies, httponly=True,
                               samesite="lax")
        return response

    @app.get("/api/web/credentials")
    async def web_get_credentials(request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
            return load_credentials(conn, u["id"])

    @app.put("/api/web/credentials")
    async def web_put_credentials(request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
        body = await read_json(request)
        with db.connect() as conn:
            return put_credentials(conn, u["id"], body)

    @app.get("/api/web/devices")
    async def web_devices(request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
            return {"devices": list_devices(conn, u["id"])}

    @app.delete("/api/web/devices/{device_id}")
    async def web_delete_device(device_id: str, request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
            if conn.execute("DELETE FROM devices WHERE id = ? AND user_id = ?", (device_id, u["id"])).rowcount != 1:
                raise ApiError(404, "no such device")
        return {"ok": True}

    @app.delete("/api/web/account")
    async def web_delete_account(request: Request):
        with db.connect() as conn:
            u = web_auth(conn, request)
            # ON DELETE CASCADE removes sessions, devices, credentials and progress.
            conn.execute("DELETE FROM users WHERE id = ?", (u["id"],))
        log.info("account %s deleted", u["id"])
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.secure_cookies, httponly=True,
                               samesite="lax")
        return response

    return app


app = create_app()
