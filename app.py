"""stream-thing-sync: accounts, encrypted API keys, and per-profile watch progress and My list for stream-thing.

One file on purpose: a FastAPI app over a single SQLite database. See README.md
for the API contract. Secrets (SECRET_KEY, GOOGLE_DESKTOP_CLIENT_SECRET) come
from the environment only.

Nothing secret is ever logged: not device tokens, session ids, Google ID
tokens, OAuth codes/verifiers or API keys. uvicorn's access log is turned off
(it would print query strings); the middleware below logs paths only.
"""
from __future__ import annotations

import asyncio
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
MAX_LIST_ENTRIES = 500
MAX_LIST_TEXT = 512
MAX_PROFILES = 12
PROFILE_ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
PROFILE_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
MAX_DEVICE_NAME_LEN = 80
MAX_BODY_BYTES = 1_000_000
MAX_NUMBER = 1e10
LAST_USED_RESOLUTION_MS = 60_000
VIDEO_ID_RE = re.compile(r"^[\x21-\x7e]{1,200}$")  # printable ASCII, no spaces
# Three letters, easy to type with a TV remote: letters only, none that look alike (I, L, O).
# 12,167 codes; with the join rate limit, guessing one is slow.
PARTY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ"
PARTY_CODE_LEN = 3
PARTY_NAME_LEN = 40
PARTY_MAX_MEMBERS = 12
PARTY_MEMBER_TIMEOUT_S = 60
PARTY_IDLE_S = 6 * 3600
PARTY_CHAT_LEN = 300
PARTY_CHAT_KEEP = 100
PARTY_CHAT_SENT = 50
PARTY_AVATAR_RE = re.compile(r"^[a-z0-9-]{1,24}$")
PARTY_SEARCH_LEN = 100
# Sync points: how long everyone gets to have the frame ready before it starts anyway, and how
# far ahead the start is set: 200 ms, the worst ping allowed for (an answer reaches everyone
# within half a round trip, through their long poll).
PARTY_SYNC_GRACE_S = 10.0
PARTY_START_LEAD_MS = 200
# A poll with ?v= waits up to this long for something to change (a long poll).
PARTY_WAIT_S = 20.0
REPORT_MESSAGE_LEN = 4000
REPORT_LOG_LEN = 300_000
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
SCHEMA_VERSION = 3
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
    profile    TEXT NOT NULL DEFAULT 'main',
    video_id   TEXT NOT NULL,
    position   REAL,
    duration   REAL,
    watched    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,  -- the device's clock: decides which write wins
    changed_at INTEGER NOT NULL,  -- the server's clock: what `since` filters on
    PRIMARY KEY (user_id, profile, video_id)
);
CREATE INDEX IF NOT EXISTS progress_since ON progress(user_id, changed_at);
CREATE TABLE IF NOT EXISTS list_items (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile    TEXT NOT NULL DEFAULT 'main',
    title_id   TEXT NOT NULL,
    type       TEXT NOT NULL,
    name       TEXT NOT NULL,
    poster     TEXT,
    added_at   INTEGER NOT NULL,
    removed    INTEGER NOT NULL,  -- a removal is kept, so it reaches the other devices
    updated_at INTEGER NOT NULL,  -- the device's clock: decides which write wins
    changed_at INTEGER NOT NULL,  -- the server's clock: what `since` filters on
    PRIMARY KEY (user_id, profile, title_id)
);
CREATE INDEX IF NOT EXISTS list_since ON list_items(user_id, changed_at);
CREATE TABLE IF NOT EXISTS profiles (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile    TEXT NOT NULL,
    name       TEXT NOT NULL,
    color      TEXT NOT NULL,
    removed    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    changed_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, profile)
);
CREATE INDEX IF NOT EXISTS profiles_since ON profiles(user_id, changed_at);
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
            if current < 3:
                # v3: profiles. Progress written before them belongs to the "main" profile.
                cols = {r[1] for r in c.execute("PRAGMA table_info(progress)")}
                if "profile" not in cols:
                    c.executescript("""
                        CREATE TABLE progress_v3 (
                            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            profile    TEXT NOT NULL DEFAULT 'main',
                            video_id   TEXT NOT NULL,
                            position   REAL,
                            duration   REAL,
                            watched    INTEGER NOT NULL,
                            updated_at INTEGER NOT NULL,
                            changed_at INTEGER NOT NULL,
                            PRIMARY KEY (user_id, profile, video_id)
                        );
                        INSERT INTO progress_v3 (user_id, profile, video_id, position, duration, watched, updated_at, changed_at)
                            SELECT user_id, 'main', video_id, position, duration, watched, updated_at, changed_at FROM progress;
                        DROP TABLE progress;
                        ALTER TABLE progress_v3 RENAME TO progress;
                        CREATE INDEX IF NOT EXISTS progress_since ON progress(user_id, changed_at);
                    """)
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

    def profile_of(request: Request) -> str:
        """Which profile a progress or My list call is for. Absent means the first one."""
        profile = request.query_params.get("profile") or "main"
        if not PROFILE_ID_RE.match(profile):
            raise ApiError(400, "invalid profile")
        return profile

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
                   WHERE user_id = ? AND profile = ? AND changed_at > ?""",
                (d["user_id"], profile_of(request), since_ms),
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
            profile = profile_of(request)
            conn.executemany(
                """INSERT INTO progress (user_id, profile, video_id, position, duration, watched, updated_at, changed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id, profile, video_id) DO UPDATE SET
                       position = excluded.position, duration = excluded.duration, watched = excluded.watched,
                       updated_at = excluded.updated_at, changed_at = excluded.changed_at
                   WHERE excluded.updated_at >= progress.updated_at""",
                [(d["user_id"], profile) + r for r in rows],
            )
        return {"ok": True, "now": sync_watermark()}

    @app.get("/api/list")
    async def get_list(request: Request, since: str = "0"):
        try:
            since_ms = int(since)
        except ValueError:
            raise ApiError(400, "since must be an integer (ms epoch)")
        with db.connect() as conn:
            d = device_auth(conn, request)
            watermark = sync_watermark()
            rows = conn.execute(
                """SELECT title_id, type, name, poster, added_at, removed, updated_at FROM list_items
                   WHERE user_id = ? AND profile = ? AND changed_at > ?""",
                (d["user_id"], profile_of(request), since_ms),
            ).fetchall()
        return {
            "list": {
                r["title_id"]: {"type": r["type"], "name": r["name"], "poster": r["poster"],
                                "addedAt": int(r["added_at"]), "removed": bool(r["removed"]),
                                "updatedAt": int(r["updated_at"])}
                for r in rows
            },
            "now": watermark,
        }

    @app.post("/api/list")
    async def post_list(request: Request):
        """My list, same rules as progress: newest updatedAt wins, removals included."""
        body = await read_json(request)
        entries = body.get("list")
        if not isinstance(entries, dict):
            raise ApiError(400, 'expected {"list": {...}}')
        if len(entries) > MAX_LIST_ENTRIES:
            raise ApiError(400, f"at most {MAX_LIST_ENTRIES} entries per request")
        t = now_ms()

        def text(entry: dict, key: str, required: bool):
            value = entry.get(key)
            if value is None and not required:
                return None
            if not isinstance(value, str) or (required and not value) or len(value) > MAX_LIST_TEXT:
                raise ApiError(400, f"{key} must be a string of at most {MAX_LIST_TEXT} characters")
            return value

        def ms(entry: dict, key: str) -> int:
            value = entry.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
                    or value <= 0:
                raise ApiError(400, f"{key} must be a positive ms epoch")
            # A device clock running ahead must not win forever: clamp to server time.
            return min(int(value), t)

        rows = []
        for title_id, entry in entries.items():
            if not VIDEO_ID_RE.match(title_id):
                raise ApiError(400, "invalid title id")
            if not isinstance(entry, dict):
                raise ApiError(400, f"entry for {title_id} must be an object")
            removed = entry.get("removed", False)
            if not isinstance(removed, bool):
                raise ApiError(400, "removed must be a boolean")
            updated = ms(entry, "updatedAt")
            if removed:
                # A removal needs nothing but the id; what was known about it is kept.
                kind = text(entry, "type", False) or ""
                name = text(entry, "name", False) or ""
                poster = None
                added = updated
            else:
                kind = text(entry, "type", True)
                name = text(entry, "name", True)
                poster = text(entry, "poster", False)
                added = ms(entry, "addedAt")
            rows.append((title_id, kind, name, poster, added, int(removed), updated, t))
        with db.connect() as conn:
            d = device_auth(conn, request)
            profile = profile_of(request)
            conn.executemany(
                """INSERT INTO list_items (user_id, profile, title_id, type, name, poster, added_at, removed, updated_at, changed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id, profile, title_id) DO UPDATE SET
                       type = CASE WHEN excluded.removed THEN list_items.type ELSE excluded.type END,
                       name = CASE WHEN excluded.removed THEN list_items.name ELSE excluded.name END,
                       poster = CASE WHEN excluded.removed THEN list_items.poster ELSE excluded.poster END,
                       added_at = CASE WHEN excluded.removed THEN list_items.added_at ELSE excluded.added_at END,
                       removed = excluded.removed, updated_at = excluded.updated_at, changed_at = excluded.changed_at
                   WHERE excluded.updated_at >= list_items.updated_at""",
                [(d["user_id"], profile) + r for r in rows],
            )
        return {"ok": True, "now": sync_watermark()}

    @app.get("/api/profiles")
    async def get_profiles(request: Request, since: str = "0"):
        try:
            since_ms = int(since)
        except ValueError:
            raise ApiError(400, "since must be an integer (ms epoch)")
        with db.connect() as conn:
            d = device_auth(conn, request)
            watermark = sync_watermark()
            rows = conn.execute(
                """SELECT profile, name, color, removed, updated_at FROM profiles
                   WHERE user_id = ? AND changed_at > ?""",
                (d["user_id"], since_ms),
            ).fetchall()
        return {
            "profiles": {
                r["profile"]: {"name": r["name"], "color": r["color"], "removed": bool(r["removed"]),
                               "updatedAt": int(r["updated_at"])}
                for r in rows
            },
            "now": watermark,
        }

    @app.post("/api/profiles")
    async def post_profiles(request: Request):
        """Profiles on the account: newest updatedAt wins. Removing one deletes its progress and list."""
        body = await read_json(request)
        entries = body.get("profiles")
        if not isinstance(entries, dict):
            raise ApiError(400, 'expected {"profiles": {...}}')
        t = now_ms()
        rows = []
        for profile, entry in entries.items():
            if not PROFILE_ID_RE.match(profile):
                raise ApiError(400, "invalid profile id")
            if not isinstance(entry, dict):
                raise ApiError(400, f"entry for {profile} must be an object")
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip() or len(name) > 40:
                raise ApiError(400, "name must be 1-40 characters")
            color = entry.get("color")
            if not isinstance(color, str) or not PROFILE_COLOR_RE.match(color):
                raise ApiError(400, "color must be #rrggbb")
            removed = entry.get("removed", False)
            if not isinstance(removed, bool):
                raise ApiError(400, "removed must be a boolean")
            if removed and profile == "main":
                raise ApiError(400, "the main profile can't be removed")
            updated = entry.get("updatedAt")
            if isinstance(updated, bool) or not isinstance(updated, (int, float)) or not math.isfinite(updated) \
                    or updated <= 0:
                raise ApiError(400, "updatedAt must be a positive ms epoch")
            rows.append((profile, name.strip(), color, int(removed), min(int(updated), t), t))
        with db.connect() as conn:
            d = device_auth(conn, request)
            live = {r[0] for r in conn.execute(
                "SELECT profile FROM profiles WHERE user_id = ? AND removed = 0", (d["user_id"],))}
            adding = {r[0] for r in rows if not r[3]} - live
            if len(live | adding) > MAX_PROFILES:
                raise ApiError(400, f"at most {MAX_PROFILES} profiles")
            for r in rows:
                cur = conn.execute(
                    """INSERT INTO profiles (user_id, profile, name, color, removed, updated_at, changed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(user_id, profile) DO UPDATE SET
                           name = excluded.name, color = excluded.color, removed = excluded.removed,
                           updated_at = excluded.updated_at, changed_at = excluded.changed_at
                       WHERE excluded.updated_at >= profiles.updated_at""",
                    (d["user_id"],) + r,
                )
                if r[3] and cur.rowcount:
                    conn.execute("DELETE FROM progress WHERE user_id = ? AND profile = ?", (d["user_id"], r[0]))
                    conn.execute("DELETE FROM list_items WHERE user_id = ? AND profile = ?", (d["user_id"], r[0]))
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

    # --- watch together ---
    #
    # A party is a code, who is in it (name, avatar, and what they're up to: a search, a
    # title they're looking at), what's on and where, and a short chat. Anyone picks what's
    # on; the host only keeps the shared position fresh while it plays. It lives in
    # memory only: nothing about it is worth keeping past a restart, and nobody needs an
    # account to join one, just the code. Each member polls about once a second; members
    # gone quiet for a minute are dropped, the host passes to whoever joined next, and an
    # empty party disappears.

    parties: dict[str, dict] = {}
    parties_lock = threading.Lock()
    party_create_limiter = TokenBucket(capacity=10, per_seconds=3600)
    party_join_limiter = TokenBucket(capacity=30, per_seconds=600)
    party_poll_limiter = TokenBucket(capacity=600, per_seconds=60)
    party_chat_limiter = TokenBucket(capacity=20, per_seconds=60)

    # code -> an event set (and replaced) whenever that party changes: long polls wait on it.
    party_events: dict[str, asyncio.Event] = {}

    def party_bump(party: dict) -> None:
        party["version"] += 1
        event = party_events.pop(party["code"], None)
        if event is not None:
            event.set()

    def party_sync_start(party: dict) -> None:
        """Everyone has the frame (or the wait is over): start at one moment, a little ahead."""
        sync = party.get("sync")
        if not sync or sync["started"]:
            return
        sync["started"] = True
        at = now_ms() + (PARTY_START_LEAD_MS if sync["play"] else 0)
        party["playback"] = {"paused": not sync["play"], "position": sync["position"], "at": at, "by": sync["by"]}
        party_bump(party)

    def party_sync_check(party: dict) -> None:
        """Start the sync point if everyone is ready, or its grace period is up."""
        sync = party.get("sync")
        if not sync or sync["started"]:
            return
        # Waiting only on those with the film open: anyone browsing the catalogue has no frame
        # to get ready, and shouldn't hold everyone else up.
        video = (party.get("media") or {}).get("videoId")
        watching = {mid for mid, info in party["members"].items() if video and info.get("ready") == video}
        if watching <= sync["ready"] or monotonic() >= sync["deadline"]:
            party_sync_start(party)

    def party_sync_timeout(code: str, sync_id: int) -> None:
        with parties_lock:
            party = parties.get(code)
            sync = party and party.get("sync")
            if sync and sync["id"] == sync_id:
                party_sync_start(party)

    def party_avatar(value) -> str:
        return value if isinstance(value, str) and PARTY_AVATAR_RE.match(value) else ""

    def party_activity(value) -> dict | None:
        """What a member is up to outside the player: a search, or a title they have open."""
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ApiError(400, "activity must be an object or null")
        kind = value.get("kind")
        if kind == "search":
            text = value.get("text")
            if not isinstance(text, str) or not text.strip():
                return None
            return {"kind": "search", "text": " ".join(text.split())[:PARTY_SEARCH_LEN], "at": now_ms()}
        if kind == "title":
            out = party_media({"videoId": value.get("id"), "type": value.get("type")})
            title = value.get("title")
            poster = value.get("poster")
            return {
                "kind": "title", "id": out["videoId"], "type": out["type"],
                "title": title[:MAX_LIST_TEXT] if isinstance(title, str) else "",
                **({"poster": poster[:MAX_LIST_TEXT]} if isinstance(poster, str) and poster.startswith("https://") else {}),
                "at": now_ms(),
            }
        raise ApiError(400, "activity.kind must be search or title")

    def party_name(body: dict) -> str:
        name = body.get("name")
        if not isinstance(name, str) or not name.strip():
            return "Guest"
        return " ".join(name.split())[:PARTY_NAME_LEN]

    def party_media(value) -> dict | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ApiError(400, "media must be an object or null")
        video_id = value.get("videoId")
        kind = value.get("type")
        if not isinstance(video_id, str) or not VIDEO_ID_RE.match(video_id):
            raise ApiError(400, "media.videoId is required")
        if not isinstance(kind, str) or not re.match(r"^[a-z]{1,20}$", kind):
            raise ApiError(400, "media.type is required")
        out = {"videoId": video_id, "type": kind}
        for key in ("title", "release", "poster", "metaId"):
            v = value.get(key)
            if isinstance(v, str) and v:
                out[key] = v[:MAX_LIST_TEXT]
        return out

    def party_playback(value, member_id: str) -> dict:
        if not isinstance(value, dict):
            raise ApiError(400, "playback must be an object")
        position = check_number(value.get("position"), "playback.position") or 0.0
        paused = value.get("paused")
        if not isinstance(paused, bool):
            raise ApiError(400, "playback.paused must be true or false")
        # `at`: the server time this holds from. Normally now; a member can schedule it a
        # moment ahead (a start everyone makes at the same instant), within ten seconds.
        at = now_ms()
        wanted = value.get("at")
        if isinstance(wanted, (int, float)) and not isinstance(wanted, bool) and abs(wanted - at) <= 10_000:
            at = int(wanted)
        return {"paused": paused, "position": position, "at": at, "by": member_id}

    def party_prune(party: dict) -> None:
        cutoff = monotonic() - PARTY_MEMBER_TIMEOUT_S
        for mid in [m for m, info in party["members"].items() if info["seen"] < cutoff]:
            del party["members"][mid]
            party_bump(party)
            party_sync_check(party)
        if party["host"] not in party["members"] and party["members"]:
            # The longest-standing member takes over.
            party["host"] = min(party["members"].items(), key=lambda kv: kv[1]["joined"])[0]
            party_bump(party)

    def party_sweep() -> None:
        stale = monotonic() - PARTY_IDLE_S
        for code in list(parties):
            party = parties[code]
            party_prune(party)
            if not party["members"] or party["touched"] < stale:
                del parties[code]

    def party_sync_view(party: dict) -> dict | None:
        sync = party.get("sync")
        if not sync:
            return None
        return {"id": sync["id"], "position": sync["position"], "play": sync["play"], "by": sync["by"],
                "started": sync["started"], "ready": sorted(sync["ready"])}

    def party_view(party: dict, member_id: str) -> dict:
        return {
            "code": party["code"],
            "version": party["version"],
            "you": member_id,
            "host": party["host"],
            "members": [
                {"id": mid, "name": info["name"], "avatar": info.get("avatar", ""), "host": mid == party["host"],
                 "activity": info.get("activity"), "ready": info.get("ready", "")}
                for mid, info in sorted(party["members"].items(), key=lambda kv: kv[1]["joined"])
            ],
            "chat": party["chat"][-PARTY_CHAT_SENT:],
            "sync": party_sync_view(party),
            "media": party["media"],
            "playback": party["playback"],
            "now": now_ms(),
        }

    def party_member(code: str, request: Request) -> tuple[dict, str]:
        """The party and the caller's member id, from the code and the x-party-token header."""
        token = request.headers.get("x-party-token", "")
        party = parties.get(code.upper())
        if party is None:
            raise ApiError(404, "no party with that code")
        party_prune(party)
        party_sync_check(party)
        wanted = sha256_hex(token) if token else ""
        for mid, info in party["members"].items():
            if token and hmac.compare_digest(info["token_hash"], wanted):
                info["seen"] = monotonic()
                party["touched"] = monotonic()
                return party, mid
        raise ApiError(403, "not in this party")

    def party_add(party: dict, name: str, avatar: str = "") -> tuple[str, str]:
        if len(party["members"]) >= PARTY_MAX_MEMBERS:
            raise ApiError(409, "the party is full")
        member_id = secrets.token_hex(4)
        token = secrets.token_urlsafe(24)
        party["members"][member_id] = {
            "name": name, "avatar": avatar, "activity": None,
            "token_hash": sha256_hex(token), "seen": monotonic(), "joined": monotonic(),
        }
        party_bump(party)
        party["touched"] = monotonic()
        return member_id, token

    @app.post("/api/party")
    async def party_create(request: Request):
        if not party_create_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many parties started, try again later")
        body = await read_json(request)
        with parties_lock:
            party_sweep()
            for _ in range(200):
                code = "".join(secrets.choice(PARTY_ALPHABET) for _ in range(PARTY_CODE_LEN))
                if code not in parties:
                    break
            else:
                raise ApiError(503, "could not make a code, try again")
            party = {"code": code, "version": 0, "host": "", "members": {}, "media": None,
                     "playback": None, "chat": [], "chat_seq": 0, "sync": None, "sync_seq": 0,
                     "touched": monotonic()}
            member_id, token = party_add(party, party_name(body), party_avatar(body.get("avatar")))
            party["host"] = member_id
            if body.get("media") is not None:
                party["media"] = {**party_media(body.get("media")), "by": member_id}
            if body.get("playback") is not None:
                party["playback"] = party_playback(body.get("playback"), member_id)
            parties[code] = party
            log.info("party %s started", code)
            return {"token": token, "party": party_view(party, member_id)}

    @app.post("/api/party/{code}/join")
    async def party_join(code: str, request: Request):
        if not party_join_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many tries, wait a minute")
        body = await read_json(request)
        with parties_lock:
            party = parties.get(code.strip().upper())
            if party is None:
                raise ApiError(404, "no party with that code")
            party_prune(party)
            member_id, token = party_add(party, party_name(body), party_avatar(body.get("avatar")))
            return {"token": token, "party": party_view(party, member_id)}

    @app.get("/api/party/{code}")
    async def party_get(code: str, request: Request):
        if not party_poll_limiter.allow(client_ip(request)):
            raise ApiError(429, "slow down")
        with parties_lock:
            party, member_id = party_member(code, request)
            seen = request.query_params.get("v")
            if seen is None or str(party["version"]) != seen:
                return party_view(party, member_id)
            # Nothing new since the version the caller has: wait for a change, so it hears of
            # one within a round trip rather than at its next poll.
            event = party_events.setdefault(party["code"], asyncio.Event())
        try:
            wait = min(PARTY_WAIT_S, max(0.0, float(request.query_params.get("wait", PARTY_WAIT_S))))
        except ValueError:
            wait = PARTY_WAIT_S
        try:
            await asyncio.wait_for(event.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass
        with parties_lock:
            party, member_id = party_member(code, request)
            return party_view(party, member_id)

    @app.post("/api/party/{code}/sync")
    async def party_sync(code: str, request: Request):
        """A sync point: everyone pauses on `position`, says when that frame is ready, and it
        starts for all at one moment (or stays paused, if `play` is false)."""
        body = await read_json(request)
        position = check_number(body.get("position"), "position") or 0.0
        play = body.get("play", True)
        if not isinstance(play, bool):
            raise ApiError(400, "play must be true or false")
        with parties_lock:
            party, member_id = party_member(code, request)
            if not party["media"]:
                raise ApiError(409, "nothing is on")
            party["sync_seq"] += 1
            sync_id = party["sync_seq"]
            party["sync"] = {"id": sync_id, "position": position, "play": play, "by": member_id,
                             "ready": set(), "started": False, "deadline": monotonic() + PARTY_SYNC_GRACE_S}
            party["playback"] = {"paused": True, "position": position, "at": now_ms(), "by": member_id}
            party_bump(party)
            asyncio.get_running_loop().call_later(PARTY_SYNC_GRACE_S, party_sync_timeout, party["code"], sync_id)
            return party_view(party, member_id)

    @app.post("/api/party/{code}/state")
    async def party_state(code: str, request: Request):
        """What is playing and play/pause/position: anyone in the party can change either."""
        body = await read_json(request)
        with parties_lock:
            party, member_id = party_member(code, request)
            if "media" in body:
                media = party_media(body.get("media"))
                same = media and party["media"] and party["media"]["videoId"] == media["videoId"]
                if not same:
                    party["media"] = {**media, "by": member_id} if media else None
                    party["playback"] = None
                    party["sync"] = None
                    party_bump(party)
            if body.get("playback") is not None:
                party["playback"] = party_playback(body.get("playback"), member_id)
                party["sync"] = None
                party_bump(party)
            return party_view(party, member_id)

    @app.post("/api/party/{code}/me")
    async def party_me(code: str, request: Request):
        """This member's name, avatar and what they're up to (each optional)."""
        body = await read_json(request)
        with parties_lock:
            party, member_id = party_member(code, request)
            info = party["members"][member_id]
            if "name" in body:
                info["name"] = party_name(body)
            if "avatar" in body:
                info["avatar"] = party_avatar(body.get("avatar"))
            if "activity" in body:
                info["activity"] = party_activity(body.get("activity"))
            if "ready" in body:
                # The video this member has loaded and is holding at its first frame, so a
                # new pick starts once everyone has it (or after a short grace period).
                ready = body.get("ready")
                info["ready"] = ready if isinstance(ready, str) and VIDEO_ID_RE.match(ready) else ""
            if "ready_sync" in body:
                # This member is paused on the sync point's frame, loaded and ready to go.
                sync = party.get("sync")
                if sync and body.get("ready_sync") == sync["id"]:
                    sync["ready"].add(member_id)
                    party_sync_check(party)
            party_bump(party)
            return party_view(party, member_id)

    @app.post("/api/party/{code}/chat")
    async def party_chat(code: str, request: Request):
        body = await read_json(request)
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ApiError(400, "say something")
        with parties_lock:
            party, member_id = party_member(code, request)
            if not party_chat_limiter.allow(party["code"] + ":" + member_id):
                raise ApiError(429, "slow down")
            info = party["members"][member_id]
            party["chat_seq"] += 1
            party["chat"].append({
                "id": party["chat_seq"], "by": member_id, "name": info["name"], "avatar": info.get("avatar", ""),
                "text": " ".join(text.split())[:PARTY_CHAT_LEN], "at": now_ms(),
            })
            del party["chat"][:-PARTY_CHAT_KEEP]
            party_bump(party)
            return party_view(party, member_id)

    @app.post("/api/party/{code}/leave")
    async def party_leave(code: str, request: Request):
        with parties_lock:
            party, member_id = party_member(code, request)
            del party["members"][member_id]
            party_bump(party)
            party_sync_check(party)
            party_prune(party)
            if not party["members"]:
                parties.pop(party["code"], None)
        return {"ok": True}

    # --- problem reports ---
    #
    # "Report a problem" in the app: what the person wrote, plus the app's own recent log,
    # crash log and playback report (stream links already stripped on the device). Each
    # report is one JSON file under DATA_DIR/reports, read by hand.

    report_limiter = TokenBucket(capacity=6, per_seconds=3600)
    reports_dir = Path(settings.data_dir) / "reports"

    @app.post("/api/report")
    async def post_report(request: Request):
        if not report_limiter.allow(client_ip(request)):
            raise ApiError(429, "too many reports from here, try again later")
        body = await read_json(request)
        message = body.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ApiError(400, "say what went wrong")
        report = {
            "at": now_ms(),
            "message": message.strip()[:REPORT_MESSAGE_LEN],
        }
        for key in ("version", "platform", "device", "page"):
            v = body.get(key)
            if isinstance(v, str):
                report[key] = v[:200]
        logs = body.get("logs")
        if isinstance(logs, dict):
            report["logs"] = {k[:40]: v[:REPORT_LOG_LEN] for k, v in list(logs.items())[:8]
                              if isinstance(k, str) and isinstance(v, str)}
        diagnostics = body.get("diagnostics")
        if isinstance(diagnostics, dict):
            report["diagnostics"] = diagnostics
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            try:
                with db.connect() as conn:
                    d = device_auth(conn, request)
                    report["account"] = {"email": d["email"], "device": d["device_name"]}
            except ApiError:
                pass  # a stale token doesn't stop the report
        report_id = time.strftime("%Y%m%d-%H%M%S", time.gmtime(report["at"] / 1000)) + "-" + secrets.token_hex(3)
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / f"{report_id}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        log.info("problem report %s", report_id)
        return {"id": report_id}

    return app


app = create_app()
