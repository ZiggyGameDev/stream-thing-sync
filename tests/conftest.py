import os
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

# app.py builds its module-level `app` at import time and fails fast without
# config, so the environment must be in place before it is imported.
os.environ["GOOGLE_CLIENT_ID"] = "web-client.apps.googleusercontent.com"
os.environ["SECRET_KEY"] = Fernet.generate_key().decode()
os.environ["PUBLIC_URL"] = "https://sync.example.test"
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="sync-import-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as appmod  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

WEB_ID = "web-client.apps.googleusercontent.com"
EXTRA_ID = "other-app.apps.googleusercontent.com"
DESKTOP_ID = "desktop-client.apps.googleusercontent.com"
DESKTOP_SECRET = "desktop-secret-value"
CSRF = {"X-Requested-With": "sync"}
VERIFIER = "v" * 43
REDIRECT = "http://127.0.0.1:53682/callback"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000_000

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += int(seconds * 1000)


def fake_token(sub, aud=WEB_ID):
    return f"good:{sub}:{aud}"


def fake_verify(credential, audience):
    """Fake Google ID tokens look like `good:<sub>[:<aud>]` (aud defaults to the web client)."""
    if not credential.startswith("good:"):
        raise ValueError("Wrong number of segments in token")
    _, sub, *rest = credential.split(":", 2)
    aud = rest[0] if rest else WEB_ID
    allowed = [audience] if isinstance(audience, str) else list(audience)
    if aud not in allowed:
        raise ValueError(f"Token has wrong audience {aud}")
    return {"sub": sub, "email": f"{sub}@example.com", "name": sub.title(), "aud": aud,
            "iss": "https://accounts.google.com"}


class FakeExchange:
    """Stands in for Google's token endpoint. Valid codes look like `code:<sub>`."""

    def __init__(self):
        self.calls = []
        self.id_token_aud = DESKTOP_ID

    def __call__(self, code, code_verifier, redirect_uri, client_id, client_secret):
        self.calls.append(dict(code=code, code_verifier=code_verifier, redirect_uri=redirect_uri,
                               client_id=client_id, client_secret=client_secret))
        if code == "unreachable":
            raise appmod.GoogleUnavailable("ConnectionError")
        if not code.startswith("code:"):
            raise appmod.GoogleCodeRejected("invalid_grant")
        return {"access_token": "ya29.x", "id_token": fake_token(code[5:], self.id_token_aud)}


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(appmod, "now_ms", c)
    return c


@pytest.fixture
def exchange(monkeypatch):
    fx = FakeExchange()
    monkeypatch.setattr(appmod, "exchange_google_code", fx)
    return fx


def make_settings(tmp_path, **overrides):
    values = dict(
        google_client_id=WEB_ID,
        secret_key=os.environ["SECRET_KEY"],
        public_url="https://sync.example.test",
        data_dir=str(tmp_path),
        google_client_ids=(WEB_ID, EXTRA_ID),
        desktop_client_id=DESKTOP_ID,
        desktop_client_secret=DESKTOP_SECRET,
    )
    values.update(overrides)
    return appmod.Settings(**values)


@pytest.fixture
def server(tmp_path, monkeypatch, clock, exchange):
    monkeypatch.setattr(appmod, "verify_google_token", fake_verify)
    return appmod.create_app(make_settings(tmp_path))


@pytest.fixture
def make_client(server):
    def make():
        return TestClient(server, base_url="https://testserver")
    return make


@pytest.fixture
def client(make_client):
    return make_client()


def sign_in(client, sub="alice"):
    """Website sign-in (session cookie)."""
    r = client.post("/api/web/google", json={"credential": fake_token(sub)}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r


def app_sign_in(client, sub="alice", name="Galaxy S23"):
    """In-app (Android) sign-in; returns the device token."""
    r = client.post("/api/auth/google", json={"id_token": fake_token(sub), "device_name": name})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def link_device(web, device_client, name="Galaxy S23"):
    """Sign `device_client` in from the app, as the same account `web` is signed in to."""
    sub = web.get("/api/web/me").json()["email"].split("@")[0]
    return app_sign_in(device_client, sub, name)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
