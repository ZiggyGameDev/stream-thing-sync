import re
import sqlite3
from pathlib import Path

import pytest

import app as appmod
from conftest import CSRF, bearer, link_device, sign_in


def db_rows(server, sql, *args):
    conn = sqlite3.connect(Path(server.state.settings.data_dir) / "sync.db")
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# --- basics ----------------------------------------------------------------


def test_healthz_and_pages(client):
    assert client.get("/healthz").json() == {"ok": True}
    for path in ("/", "/link", "/link?code=ABCD-2345"):
        r = client.get(path)
        assert r.status_code == 200
        assert "test-client.apps.googleusercontent.com" in r.text
        assert "accounts.google.com/gsi/client" in r.text
        assert "nonce-" in r.headers["content-security-policy"]


def test_legal_pages(client):
    assert 'href="/privacy"' in client.get("/").text and 'href="/terms"' in client.get("/").text
    privacy = client.get("/privacy")
    assert privacy.status_code == 200 and "not shared" in privacy.text and "Delete account" in privacy.text
    terms = client.get("/terms")
    assert terms.status_code == 200 and "as-is" in terms.text
    assert "{{" not in privacy.text + terms.text


def test_unknown_route_is_json_error(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.json() == {"error": "not found"}


def test_missing_config_fails_fast(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        appmod.Settings.from_env()


# --- web sign-in -------------------------------------------------------------


def test_google_sign_in_creates_user_and_cookie(server, client):
    r = sign_in(client, "alice")
    assert r.json()["email"] == "alice@example.com"
    cookie = r.headers["set-cookie"]
    assert appmod.SESSION_COOKIE in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "samesite=lax" in cookie.lower()
    assert client.get("/api/web/me").json()["email"] == "alice@example.com"
    users = db_rows(server, "SELECT google_sub, email FROM users")
    assert users == [("alice", "alice@example.com")]
    # Session id is stored hashed, not as the cookie value.
    token = client.cookies.get(appmod.SESSION_COOKIE)
    assert token and not db_rows(server, "SELECT 1 FROM sessions WHERE id_hash = ?", token)
    # Signing in again reuses the same user.
    sign_in(client, "alice")
    assert len(db_rows(server, "SELECT id FROM users")) == 1


def test_bad_google_credential_rejected(client):
    r = client.post("/api/web/google", json={"credential": "forged"}, headers=CSRF)
    assert r.status_code == 401 and "error" in r.json()
    assert client.get("/api/web/me").status_code == 401


def test_csrf_header_required(client):
    r = client.post("/api/web/google", json={"credential": "good:alice"})
    assert r.status_code == 403
    sign_in(client)
    for method, path, body in [
        ("PUT", "/api/web/credentials", {"credentials": {"torbox": "x"}}),
        ("POST", "/api/web/link/approve", {"code": "ABCD-2345"}),
        ("DELETE", "/api/web/account", None),
        ("POST", "/api/web/logout", None),
    ]:
        r = client.request(method, path, json=body)
        assert r.status_code == 403, (method, path)
    # GET doesn't need it, and the account is still there.
    assert client.get("/api/web/me").status_code == 200


def test_web_logout_revokes_session(server, client):
    sign_in(client)
    token = client.cookies.get(appmod.SESSION_COOKIE)
    assert client.post("/api/web/logout", headers=CSRF).json() == {"ok": True}
    assert db_rows(server, "SELECT COUNT(*) FROM sessions") == [(0,)]
    client.cookies.set(appmod.SESSION_COOKIE, token, domain="testserver")
    assert client.get("/api/web/me").status_code == 401


# --- device link ---------------------------------------------------------------


def test_full_device_link_flow(make_client):
    web, tv = make_client(), make_client()
    sign_in(web, "alice")
    start = tv.post("/api/link/start", json={"device_name": "Living room TV"})
    assert start.status_code == 200
    s = start.json()
    assert re.fullmatch(r"[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}", s["code"])
    assert len(s["device_secret"]) >= 43
    assert s["verify_url"] == "https://sync.example.test/link"
    assert s["expires_in"] == 600 and s["interval"] == 5

    assert tv.post("/api/link/poll", json={"device_secret": s["device_secret"]}).json() == {"status": "pending"}

    # Lowercase, dashless entry works; lookup shows the device name.
    typed = s["code"].replace("-", "").lower()
    assert web.get(f"/api/web/link/lookup?code={typed}").json()["device_name"] == "Living room TV"
    r = web.post("/api/web/link/approve", json={"code": typed}, headers=CSRF)
    assert r.json() == {"ok": True, "device_name": "Living room TV"}
    # Can't approve twice.
    assert web.post("/api/web/link/approve", json={"code": s["code"]}, headers=CSRF).status_code == 404

    r = tv.post("/api/link/poll", json={"device_secret": s["device_secret"]})
    body = r.json()
    assert body["status"] == "approved"
    assert body["account"] == {"email": "alice@example.com", "name": "Alice"}
    token = body["token"]
    assert len(token) >= 43

    # Consumed: polling again is gone.
    assert tv.post("/api/link/poll", json={"device_secret": s["device_secret"]}).status_code == 410

    me = tv.get("/api/me", headers=bearer(token)).json()
    assert me["email"] == "alice@example.com" and me["device"]["name"] == "Living room TV"
    devices = web.get("/api/web/devices").json()["devices"]
    assert [d["name"] for d in devices] == ["Living room TV"]
    assert devices[0]["id"] == me["device"]["id"]


def test_link_code_expires(make_client, clock):
    web, tv = make_client(), make_client()
    sign_in(web)
    s = tv.post("/api/link/start", json={"device_name": "TV"}).json()
    clock.advance(601)
    assert web.post("/api/web/link/approve", json={"code": s["code"]}, headers=CSRF).status_code in (404, 410)
    r = tv.post("/api/link/poll", json={"device_secret": s["device_secret"]})
    assert r.status_code == 410 and r.json() == {"error": "expired"}


def test_poll_unknown_secret_and_bad_input(client):
    assert client.post("/api/link/poll", json={"device_secret": "nope"}).status_code == 410
    assert client.post("/api/link/poll", json={}).status_code == 400
    assert client.post("/api/link/start", json={}).status_code == 400
    assert client.post("/api/link/start", content=b"not json").status_code == 400


def test_approve_unknown_code_404(client):
    sign_in(client)
    assert client.post("/api/web/link/approve", json={"code": "ABCD-2345"}, headers=CSRF).status_code == 404
    assert client.post("/api/web/link/approve", json={"code": "!!"}, headers=CSRF).status_code == 404


def test_poll_rate_limited(server, client):
    server.state.poll_min_interval = 2
    s = client.post("/api/link/start", json={"device_name": "TV"}).json()
    assert client.post("/api/link/poll", json={"device_secret": s["device_secret"]}).status_code == 200
    r = client.post("/api/link/poll", json={"device_secret": s["device_secret"]})
    assert r.status_code == 429 and "error" in r.json()


def test_link_start_rate_limited_per_ip(client):
    codes = [client.post("/api/link/start", json={"device_name": "TV"}, headers={"CF-Connecting-IP": "1.2.3.4"})
             .status_code for _ in range(12)]
    assert codes[0] == 200 and codes[-1] == 429
    # A different client IP is unaffected.
    assert client.post("/api/link/start", json={"device_name": "TV"},
                       headers={"CF-Connecting-IP": "5.6.7.8"}).status_code == 200


# --- device API ---------------------------------------------------------------


def test_bad_token_401(client):
    for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"}):
        for method, path in [("GET", "/api/me"), ("GET", "/api/credentials"), ("GET", "/api/progress"),
                             ("POST", "/api/logout")]:
            r = client.request(method, path, headers=headers)
            assert r.status_code == 401, (headers, path)
            assert "error" in r.json()


def test_credentials_put_get_merge_remove_and_encrypted(server, make_client):
    web, phone = make_client(), make_client()
    sign_in(web)
    token = link_device(web, phone)
    h = bearer(token)

    assert phone.get("/api/credentials", headers=h).json() == {"credentials": {}, "updated_at": None}

    r = phone.put("/api/credentials", headers=h, json={"credentials": {"torbox": "tb-SECRET-123", "mdblist": "md-SECRET-456"}})
    assert r.status_code == 200
    assert r.json()["credentials"] == {"torbox": "tb-SECRET-123", "mdblist": "md-SECRET-456"}
    assert isinstance(r.json()["updated_at"], int)

    # Merge: setting one key leaves the others alone.
    r = phone.put("/api/credentials", headers=h, json={"credentials": {"poster": "po-SECRET-789"}})
    assert r.json()["credentials"] == {"torbox": "tb-SECRET-123", "mdblist": "md-SECRET-456", "poster": "po-SECRET-789"}

    # Empty string and null remove.
    r = phone.put("/api/credentials", headers=h, json={"credentials": {"torbox": "", "mdblist": None}})
    assert r.json()["credentials"] == {"poster": "po-SECRET-789"}

    # Same shape on the web API, and the web can write too.
    assert web.get("/api/web/credentials").json()["credentials"] == {"poster": "po-SECRET-789"}
    web.put("/api/web/credentials", headers=CSRF, json={"credentials": {"torbox": "tb-WEB-000"}})
    assert phone.get("/api/credentials", headers=h).json()["credentials"] == {"poster": "po-SECRET-789", "torbox": "tb-WEB-000"}

    # Validation.
    assert phone.put("/api/credentials", headers=h, json={"credentials": {"simkl": "x"}}).status_code == 400
    assert phone.put("/api/credentials", headers=h, json={"credentials": {"torbox": "x" * 513}}).status_code == 400
    assert phone.put("/api/credentials", headers=h, json={"credentials": {"torbox": 5}}).status_code == 400
    assert phone.put("/api/credentials", headers=h, json={"torbox": "x"}).status_code == 400

    # Encrypted at rest: plaintext appears nowhere in the database files.
    raw = b"".join(p.read_bytes() for p in Path(server.state.settings.data_dir).glob("sync.db*"))
    for secret in (b"po-SECRET-789", b"tb-WEB-000", b"tb-SECRET-123"):
        assert secret not in raw


def test_progress_newest_wins_and_since(make_client, clock):
    web, a, b = make_client(), make_client(), make_client()
    sign_in(web)
    ta, tb = link_device(web, a, "Phone"), link_device(web, b, "TV")

    t0 = clock()
    r = a.post("/api/progress", headers=bearer(ta), json={"progress": {
        "tt0133093": {"position": 120.5, "duration": 8160, "watched": False, "updatedAt": t0 - 1000},
        "tt0944947:1:3": {"position": None, "duration": None, "watched": True, "updatedAt": t0 - 1000},
    }})
    assert r.json() == {"ok": True, "now": t0 - 1}

    full = b.get("/api/progress", headers=bearer(tb)).json()
    assert full["now"] == t0 - 1
    assert full["progress"]["tt0133093"] == {"position": 120.5, "duration": 8160, "watched": False, "updatedAt": t0 - 1000}
    assert full["progress"]["tt0944947:1:3"]["watched"] is True

    clock.advance(10)
    # Older update loses, newer wins, equal wins.
    b.post("/api/progress", headers=bearer(tb), json={"progress": {
        "tt0133093": {"position": 5, "duration": 8160, "watched": False, "updatedAt": t0 - 5000},
        "tt0944947:1:3": {"position": 30, "duration": 3000, "watched": False, "updatedAt": t0 - 1000},
        "kitsu:11469:11": {"position": 60, "duration": 1440, "watched": False, "updatedAt": t0 + 9000},
    }})
    since = a.get(f"/api/progress?since={full['now'] + 1}", headers=bearer(ta)).json()["progress"]  # = t0
    assert set(since) == {"tt0944947:1:3", "kitsu:11469:11"}  # the losing write didn't count as a change
    assert since["tt0944947:1:3"]["position"] == 30
    allp = a.get("/api/progress", headers=bearer(ta)).json()["progress"]
    assert allp["tt0133093"]["position"] == 120.5

    clock.advance(10)
    assert a.get(f"/api/progress?since={clock()}", headers=bearer(ta)).json()["progress"] == {}


def test_progress_since_uses_server_time_not_device_clock(make_client, clock):
    """A device whose clock runs behind pushes after another device pulled; the
    next pull with since=<last now> must still return the entry."""
    web, fast, slow = make_client(), make_client(), make_client()
    sign_in(web)
    tf, ts = link_device(web, fast, "PC"), link_device(web, slow, "TV")

    clock.advance(60)
    last_now = fast.get("/api/progress", headers=bearer(tf)).json()["now"]

    clock.advance(5)
    behind = clock() - 3_600_000  # the TV thinks it's an hour earlier
    slow.post("/api/progress", headers=bearer(ts), json={"progress": {
        "tt0133093": {"position": 42, "duration": 8160, "watched": False, "updatedAt": behind}}})

    clock.advance(1)
    got = fast.get(f"/api/progress?since={last_now}", headers=bearer(tf)).json()
    assert got["progress"]["tt0133093"]["position"] == 42
    assert got["progress"]["tt0133093"]["updatedAt"] == behind
    # And nothing is repeated once the client moves on.
    assert fast.get(f"/api/progress?since={got['now']}", headers=bearer(tf)).json()["progress"] == {}


def test_write_in_same_millisecond_as_pull_is_not_missed(make_client, clock):
    web, a, b = make_client(), make_client(), make_client()
    sign_in(web)
    ta, tb = link_device(web, a), link_device(web, b)
    last_now = a.get("/api/progress", headers=bearer(ta)).json()["now"]
    # Clock has not moved: b's write lands in the same millisecond as a's pull.
    b.post("/api/progress", headers=bearer(tb), json={"progress": {"tt1": {"watched": True, "updatedAt": 1}}})
    assert "tt1" in a.get(f"/api/progress?since={last_now}", headers=bearer(ta)).json()["progress"]


def test_progress_isolated_between_users(make_client):
    w1, w2, d1, d2 = make_client(), make_client(), make_client(), make_client()
    sign_in(w1, "alice"); sign_in(w2, "bob")
    t1, t2 = link_device(w1, d1), link_device(w2, d2)
    d1.post("/api/progress", headers=bearer(t1), json={"progress": {"tt1": {"watched": True, "updatedAt": 1}}})
    assert d2.get("/api/progress", headers=bearer(t2)).json()["progress"] == {}


def test_progress_validation(make_client):
    web, d = make_client(), make_client()
    sign_in(web)
    h = bearer(link_device(web, d))

    def post(progress):
        return d.post("/api/progress", headers=h, json={"progress": progress}).status_code

    ok = {"position": 1, "duration": 2, "watched": False, "updatedAt": 1000}
    assert post({"tt1": ok}) == 200
    assert post({"x" * 201: ok}) == 400
    assert post({"has space": ok}) == 400
    assert post({"tt1": {**ok, "position": -1}}) == 400
    assert post({"tt1": {**ok, "position": "1"}}) == 400
    assert post({"tt1": {**ok, "watched": "yes"}}) == 400
    assert post({"tt1": {**ok, "updatedAt": None}}) == 400
    assert post({f"tt{i}": ok for i in range(501)}) == 400
    assert post({f"tt{i}": ok for i in range(500)}) == 200
    assert d.get("/api/progress?since=abc", headers=h).status_code == 400


# --- revocation ------------------------------------------------------------------


def test_device_logout_revokes_token(make_client):
    web, d = make_client(), make_client()
    sign_in(web)
    token = link_device(web, d)
    assert d.post("/api/logout", headers=bearer(token)).json() == {"ok": True}
    assert d.get("/api/me", headers=bearer(token)).status_code == 401
    assert web.get("/api/web/devices").json()["devices"] == []


def test_web_revokes_device(make_client):
    web, d1, d2 = make_client(), make_client(), make_client()
    sign_in(web)
    t1, t2 = link_device(web, d1, "Phone"), link_device(web, d2, "TV")
    devices = {x["name"]: x["id"] for x in web.get("/api/web/devices").json()["devices"]}
    assert web.delete(f"/api/web/devices/{devices['TV']}", headers=CSRF).json() == {"ok": True}
    assert d2.get("/api/me", headers=bearer(t2)).status_code == 401
    assert d1.get("/api/me", headers=bearer(t1)).status_code == 200
    assert web.delete(f"/api/web/devices/{devices['TV']}", headers=CSRF).status_code == 404


def test_cannot_revoke_someone_elses_device(make_client):
    alice, bob, d = make_client(), make_client(), make_client()
    sign_in(alice, "alice"); sign_in(bob, "bob")
    token = link_device(alice, d)
    dev_id = d.get("/api/me", headers=bearer(token)).json()["device"]["id"]
    assert bob.delete(f"/api/web/devices/{dev_id}", headers=CSRF).status_code == 404
    assert d.get("/api/me", headers=bearer(token)).status_code == 200


def test_account_delete(server, make_client):
    web, d = make_client(), make_client()
    sign_in(web)
    token = link_device(web, d)
    d.put("/api/credentials", headers=bearer(token), json={"credentials": {"torbox": "tb"}})
    d.post("/api/progress", headers=bearer(token), json={"progress": {"tt1": {"watched": True, "updatedAt": 1}}})

    assert web.delete("/api/web/account", headers=CSRF).json() == {"ok": True}
    assert d.get("/api/me", headers=bearer(token)).status_code == 401
    assert web.get("/api/web/me").status_code == 401
    for table in ("users", "sessions", "devices", "credentials", "progress", "link_requests"):
        assert db_rows(server, f"SELECT COUNT(*) FROM {table}") == [(0,)], table


def test_last_used_updates_at_most_once_a_minute(server, make_client, clock):
    web, d = make_client(), make_client()
    sign_in(web)
    token = link_device(web, d)
    first = db_rows(server, "SELECT last_used_at FROM devices")[0][0]
    clock.advance(30)
    d.get("/api/me", headers=bearer(token))
    assert db_rows(server, "SELECT last_used_at FROM devices")[0][0] == first
    clock.advance(31)
    d.get("/api/me", headers=bearer(token))
    assert db_rows(server, "SELECT last_used_at FROM devices")[0][0] == clock()
