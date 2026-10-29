import os
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

# app.py builds its module-level `app` at import time and fails fast without
# config, so the environment must be in place before it is imported.
os.environ["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com"
os.environ["SECRET_KEY"] = Fernet.generate_key().decode()
os.environ["PUBLIC_URL"] = "https://sync.example.test"
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="sync-import-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as appmod  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CSRF = {"X-Requested-With": "sync"}


class Clock:
    def __init__(self):
        self.t = 1_800_000_000_000

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += int(seconds * 1000)


def fake_verify(credential, client_id):
    assert client_id == "test-client.apps.googleusercontent.com"
    if not credential.startswith("good:"):
        raise ValueError("Wrong number of segments in token")
    sub = credential.split(":", 1)[1]
    return {"sub": sub, "email": f"{sub}@example.com", "name": sub.title(), "iss": "https://accounts.google.com"}


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(appmod, "now_ms", c)
    return c


@pytest.fixture
def server(tmp_path, monkeypatch, clock):
    monkeypatch.setattr(appmod, "verify_google_token", fake_verify)
    settings = appmod.Settings(
        google_client_id=os.environ["GOOGLE_CLIENT_ID"],
        secret_key=os.environ["SECRET_KEY"],
        public_url="https://sync.example.test",
        data_dir=str(tmp_path),
    )
    application = appmod.create_app(settings)
    application.state.poll_min_interval = 0
    return application


@pytest.fixture
def make_client(server):
    def make():
        return TestClient(server, base_url="https://testserver")
    return make


@pytest.fixture
def client(make_client):
    return make_client()


def sign_in(client, sub="alice"):
    r = client.post("/api/web/google", json={"credential": f"good:{sub}"}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r


def link_device(web, device_client, name="Galaxy S23"):
    start = device_client.post("/api/link/start", json={"device_name": name}).json()
    r = web.post("/api/web/link/approve", json={"code": start["code"]}, headers=CSRF)
    assert r.status_code == 200, r.text
    r = device_client.post("/api/link/poll", json={"device_secret": start["device_secret"]})
    assert r.json()["status"] == "approved", r.text
    return r.json()["token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
