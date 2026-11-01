import re
import sqlite3
from pathlib import Path

import pytest

import app as appmod
from conftest import (CSRF, DESKTOP_ID, DESKTOP_SECRET, EXTRA_ID, REDIRECT, VERIFIER, app_sign_in, bearer,
                      fake_token, link_device, make_settings, sign_in)


def db_rows(server, sql, *args):
    conn = sqlite3.connect(Path(server.state.settings.data_dir) / "sync.db")
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# --- basics ----------------------------------------------------------------


def test_healthz_and_pages(client):
    assert client.get("/healthz").json() == {"ok": True}
    r = client.get("/")
    assert r.status_code == 200
    assert "web-client.apps.googleusercontent.com" in r.text
    assert "accounts.google.com/gsi/client" in r.text
    assert "nonce-" in r.headers["content-security-policy"]
    assert "inside the stream-thing app" in r.text


def test_device_code_flow_is_gone(client):
    assert client.get("/link").status_code == 404
    for path in ("/api/link/start", "/api/link/poll", "/api/web/link/approve"):
        assert client.post(path, json={}).status_code in (404, 405)
    assert client.get("/api/web/link/lookup?code=ABCD2345").status_code == 404


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
    r = client.post("/api/web/google", json={"credential": fake_token("alice")})
    assert r.status_code == 403
    sign_in(client)
    for method, path, body in [
        ("PUT", "/api/web/credentials", {"credentials": {"torbox": "x"}}),
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
    for table in ("users", "sessions", "devices", "credentials", "progress"):
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


# --- in-app sign-in: Android (ID token) ---------------------------------------


def test_app_google_sign_in_is_sign_up(server, client):
    r = client.post("/api/auth/google", json={"id_token": fake_token("carol"), "device_name": "  Pixel   8 "})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["account"] == {"email": "carol@example.com", "name": "Carol"}
    assert len(body["token"]) >= 43
    me = client.get("/api/me", headers=bearer(body["token"])).json()
    assert me["email"] == "carol@example.com" and me["device"]["name"] == "Pixel 8"
    assert db_rows(server, "SELECT google_sub FROM users") == [("carol",)]
    # Only the hash of the token is stored.
    assert not db_rows(server, "SELECT 1 FROM devices WHERE token_hash = ?", body["token"])
    # Signing in again (another device) reuses the user and adds a device.
    app_sign_in(client, "carol", "Shield TV")
    assert db_rows(server, "SELECT COUNT(*) FROM users") == [(1,)]
    assert db_rows(server, "SELECT COUNT(*) FROM devices") == [(2,)]


def test_app_and_web_share_the_account(make_client):
    web, phone = make_client(), make_client()
    token = app_sign_in(phone, "alice", "Phone")
    phone.put("/api/credentials", headers=bearer(token), json={"credentials": {"torbox": "tb"}})
    sign_in(web, "alice")
    assert web.get("/api/web/credentials").json()["credentials"] == {"torbox": "tb"}
    assert [d["name"] for d in web.get("/api/web/devices").json()["devices"]] == ["Phone"]


def test_app_google_accepts_listed_audiences_only(client):
    for aud in ("web-client.apps.googleusercontent.com", EXTRA_ID):
        r = client.post("/api/auth/google", json={"id_token": fake_token("a", aud), "device_name": "x"})
        assert r.status_code == 200, aud
    r = client.post("/api/auth/google", json={"id_token": fake_token("a", "someone-else"), "device_name": "x"})
    assert r.status_code == 401
    # The website only takes its own client ID.
    r = client.post("/api/web/google", json={"credential": fake_token("a", EXTRA_ID)}, headers=CSRF)
    assert r.status_code == 401


def test_web_client_id_always_accepted_by_app(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import conftest
    monkeypatch.setattr(appmod, "verify_google_token", conftest.fake_verify)
    application = appmod.create_app(make_settings(tmp_path, google_client_ids=()))
    c = TestClient(application, base_url="https://testserver")
    assert c.post("/api/auth/google", json={"id_token": fake_token("a"), "device_name": "x"}).status_code == 200


def test_app_google_bad_input(client):
    assert client.post("/api/auth/google", json={"id_token": "forged", "device_name": "x"}).status_code == 401
    assert client.post("/api/auth/google", json={"id_token": fake_token("a")}).status_code == 400
    assert client.post("/api/auth/google", json={"id_token": fake_token("a"), "device_name": " "}).status_code == 400
    assert client.post("/api/auth/google", json={"device_name": "x"}).status_code == 400
    assert client.post("/api/auth/google", content=b"nope").status_code == 400


def test_app_auth_rate_limited_per_ip(client):
    def go(ip):
        return client.post("/api/auth/google", json={"id_token": fake_token("a"), "device_name": "x"},
                           headers={"CF-Connecting-IP": ip}).status_code
    codes = [go("1.2.3.4") for _ in range(12)]
    assert codes[0] == 200 and codes[-1] == 429
    assert go("5.6.7.8") == 200
    # The desktop endpoint shares the per-IP budget.
    r = client.post("/api/auth/google-code", headers={"CF-Connecting-IP": "1.2.3.4"},
                    json={"code": "code:a", "code_verifier": VERIFIER, "redirect_uri": REDIRECT, "device_name": "x"})
    assert r.status_code == 429


# --- in-app sign-in: Windows (authorization code + PKCE) -----------------------


def test_app_google_code_flow(server, client, exchange):
    r = client.post("/api/auth/google-code", json={
        "code": "code:dave", "code_verifier": VERIFIER, "redirect_uri": REDIRECT, "device_name": "Gaming PC"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["account"] == {"email": "dave@example.com", "name": "Dave"}
    me = client.get("/api/me", headers=bearer(body["token"])).json()
    assert me["device"]["name"] == "Gaming PC"
    # The server, not the app, supplies the desktop client ID and secret.
    assert exchange.calls == [{"code": "code:dave", "code_verifier": VERIFIER, "redirect_uri": REDIRECT,
                               "client_id": DESKTOP_ID, "client_secret": DESKTOP_SECRET}]


def test_app_google_code_rejections(client, exchange):
    ips = iter(range(1, 1000))

    def go(**overrides):
        body = {"code": "code:dave", "code_verifier": VERIFIER, "redirect_uri": REDIRECT, "device_name": "PC"}
        body.update(overrides)
        # A fresh client IP per call keeps the per-IP rate limit out of this test.
        return client.post("/api/auth/google-code", json=body,
                           headers={"CF-Connecting-IP": f"10.0.0.{next(ips)}"}).status_code

    assert go(code="bad") == 401
    assert go(code="unreachable") == 502
    assert go(code="") == 400
    assert go(code_verifier="short") == 400
    assert go(code_verifier="v" * 129) == 400
    assert go(device_name=None) == 400
    for uri in ("https://127.0.0.1:5000/cb", "http://127.0.0.1/cb", "http://evil.com:5000/cb",
                "http://127.0.0.1:5000@evil.com/cb", "http://user@127.0.0.1:5000/cb",
                "http://127.0.0.1.evil.com:5000/cb", "http://[::1]:5000/cb", "http://127.0.0.1:99999/cb",
                "myapp://callback", "", None):
        assert go(redirect_uri=uri) == 400, uri
    for uri in ("http://127.0.0.1:5000/cb", "http://localhost:61234/", "http://localhost:8080"):
        assert go(redirect_uri=uri) == 200, uri
    # The returned ID token must be for the desktop client.
    exchange.id_token_aud = "web-client.apps.googleusercontent.com"
    assert go() == 401
    # Only the 6 well-formed requests reached Google; bad input is rejected up front.
    assert len(exchange.calls) == 6


def test_app_google_code_503_without_secret(tmp_path, monkeypatch, exchange):
    from fastapi.testclient import TestClient

    import conftest
    monkeypatch.setattr(appmod, "verify_google_token", conftest.fake_verify)
    application = appmod.create_app(make_settings(tmp_path, desktop_client_secret=""))
    c = TestClient(application, base_url="https://testserver")
    r = c.post("/api/auth/google-code", json={
        "code": "code:dave", "code_verifier": VERIFIER, "redirect_uri": REDIRECT, "device_name": "PC"})
    assert r.status_code == 503 and "error" in r.json()
    assert exchange.calls == []


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "web")
    monkeypatch.setenv("GOOGLE_CLIENT_IDS", " web , extra ,,")
    monkeypatch.setenv("GOOGLE_DESKTOP_CLIENT_ID", "desk")
    monkeypatch.delenv("GOOGLE_DESKTOP_CLIENT_SECRET", raising=False)
    s = appmod.Settings.from_env()
    assert s.app_audiences == ["web", "extra"]
    assert s.desktop_client_id == "desk" and s.desktop_client_secret == ""


def test_old_link_table_is_dropped(tmp_path):
    import sqlite3 as sq
    conn = sq.connect(tmp_path / "sync.db")
    conn.executescript("CREATE TABLE schema_version (version INTEGER NOT NULL); INSERT INTO schema_version VALUES (1);"
                       "CREATE TABLE link_requests (secret_hash TEXT PRIMARY KEY);")
    conn.close()
    appmod.create_app(make_settings(tmp_path))
    names = {r[0] for r in db_rows_path(tmp_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "link_requests" not in names and "progress" in names
    assert db_rows_path(tmp_path, "SELECT version FROM schema_version") == [(appmod.SCHEMA_VERSION,)]


def db_rows_path(path, sql):
    conn = sqlite3.connect(Path(path) / "sync.db")
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


# --- debrid credentials ----------------------------------------------------------


def test_debrid_credentials(make_client):
    web, d = make_client(), make_client()
    sign_in(web)
    h = bearer(link_device(web, d))
    r = d.put("/api/credentials", headers=h, json={"credentials": {
        "debrid_service": "realdebrid", "realdebrid": "rd-TOKEN", "torbox": "tb-KEY"}})
    assert r.status_code == 200
    assert r.json()["credentials"] == {"debrid_service": "realdebrid", "realdebrid": "rd-TOKEN", "torbox": "tb-KEY"}
    r = web.put("/api/web/credentials", headers=CSRF, json={"credentials": {"debrid_service": "torbox"}})
    assert r.json()["credentials"]["debrid_service"] == "torbox"
    assert d.put("/api/credentials", headers=h,
                 json={"credentials": {"debrid_service": "alldebrid"}}).status_code == 400
    r = d.put("/api/credentials", headers=h, json={"credentials": {"debrid_service": None, "realdebrid": ""}})
    assert r.json()["credentials"] == {"torbox": "tb-KEY"}


# ------------------------------------------------------------------- my list ----

def test_list_sync_newest_wins_and_removals_travel(make_client, clock):
    web, a, b = make_client(), make_client(), make_client()
    sign_in(web)
    ta, tb = link_device(web, a, "PC"), link_device(web, b, "TV")
    t0 = clock()

    r = a.post("/api/list", headers=bearer(ta), json={"list": {
        "tt5875444": {"type": "series", "name": "Slow Horses", "poster": "https://x/p.jpg", "addedAt": t0 - 100, "updatedAt": t0 - 100},
        "tt0133093": {"type": "movie", "name": "The Matrix", "poster": None, "addedAt": t0 - 100, "updatedAt": t0 - 100},
    }})
    assert r.json() == {"ok": True, "now": t0 - 1}
    full = b.get("/api/list", headers=bearer(tb)).json()
    assert full["list"]["tt5875444"] == {"type": "series", "name": "Slow Horses", "poster": "https://x/p.jpg",
                                         "addedAt": t0 - 100, "removed": False, "updatedAt": t0 - 100}

    clock.advance(10)
    # The TV removes the film; an older re-add from elsewhere loses.
    b.post("/api/list", headers=bearer(tb), json={"list": {"tt0133093": {"removed": True, "updatedAt": t0 + 5}}})
    a.post("/api/list", headers=bearer(ta), json={"list": {
        "tt0133093": {"type": "movie", "name": "The Matrix", "addedAt": t0 - 50, "updatedAt": t0 - 50}}})
    since = a.get(f"/api/list?since={full['now'] + 1}", headers=bearer(ta)).json()["list"]
    assert set(since) == {"tt0133093"}
    assert since["tt0133093"]["removed"] is True
    # What was known about it survives the removal.
    assert since["tt0133093"]["name"] == "The Matrix"

    clock.advance(10)
    a.post("/api/list", headers=bearer(ta), json={"list": {
        "tt0133093": {"type": "movie", "name": "The Matrix", "addedAt": clock(), "updatedAt": clock()}}})
    assert b.get("/api/list", headers=bearer(tb)).json()["list"]["tt0133093"]["removed"] is False


def test_list_isolated_and_validated(make_client):
    w1, w2, d1, d2 = make_client(), make_client(), make_client(), make_client()
    sign_in(w1, "alice"); sign_in(w2, "bob")
    t1, t2 = link_device(w1, d1), link_device(w2, d2)
    ok = {"type": "series", "name": "X", "addedAt": 1000, "updatedAt": 1000}
    assert d1.post("/api/list", headers=bearer(t1), json={"list": {"tt1": ok}}).status_code == 200
    assert d2.get("/api/list", headers=bearer(t2)).json()["list"] == {}

    def post(entries):
        return d1.post("/api/list", headers=bearer(t1), json={"list": entries}).status_code

    assert post({"x" * 201: ok}) == 400
    assert post({"tt1": {**ok, "name": ""}}) == 400
    assert post({"tt1": {**ok, "updatedAt": -1}}) == 400
    assert post({"tt1": {**ok, "removed": "yes"}}) == 400
    assert post({"tt1": {"removed": True, "updatedAt": 2000}}) == 200
    assert post({f"tt{i}": ok for i in range(501)}) == 400
    assert d1.get("/api/list").status_code == 401


# ------------------------------------------------------------------ profiles ----

def test_profiles_keep_progress_and_list_apart(make_client):
    web, a = make_client(), make_client()
    sign_in(web)
    h = bearer(link_device(web, a))
    entry = {"position": 10, "duration": 100, "watched": False, "updatedAt": 1000}
    a.post("/api/progress", headers=h, json={"progress": {"tt1": entry}})
    a.post("/api/progress?profile=kid-1", headers=h, json={"progress": {"tt2": entry}})
    assert set(a.get("/api/progress", headers=h).json()["progress"]) == {"tt1"}
    assert set(a.get("/api/progress?profile=main", headers=h).json()["progress"]) == {"tt1"}
    assert set(a.get("/api/progress?profile=kid-1", headers=h).json()["progress"]) == {"tt2"}

    item = {"type": "series", "name": "X", "addedAt": 1000, "updatedAt": 1000}
    a.post("/api/list?profile=kid-1", headers=h, json={"list": {"tt9": item}})
    assert a.get("/api/list", headers=h).json()["list"] == {}
    assert set(a.get("/api/list?profile=kid-1", headers=h).json()["list"]) == {"tt9"}
    assert a.get("/api/progress?profile=Bad%20Id", headers=h).status_code == 400


def test_profiles_sync_and_removal_clears_their_data(make_client, clock):
    web, a, b = make_client(), make_client(), make_client()
    sign_in(web)
    ha, hb = bearer(link_device(web, a)), bearer(link_device(web, b))
    t = clock()
    r = a.post("/api/profiles", headers=ha, json={"profiles": {
        "main": {"name": "Ziggy", "color": "#ff4d5e", "updatedAt": t},
        "kid-1": {"name": "Kids", "color": "#3ddc84", "updatedAt": t},
    }})
    assert r.status_code == 200
    got = b.get("/api/profiles", headers=hb).json()["profiles"]
    assert got["kid-1"] == {"name": "Kids", "color": "#3ddc84", "removed": False, "updatedAt": t}

    entry = {"position": 1, "duration": 2, "watched": False, "updatedAt": 1000}
    b.post("/api/progress?profile=kid-1", headers=hb, json={"progress": {"tt1": entry}})
    clock.advance(5)
    a.post("/api/profiles", headers=ha, json={"profiles": {
        "kid-1": {"name": "Kids", "color": "#3ddc84", "removed": True, "updatedAt": clock()}}})
    assert b.get("/api/progress?profile=kid-1", headers=hb).json()["progress"] == {}
    assert b.get("/api/profiles", headers=hb).json()["profiles"]["kid-1"]["removed"] is True
    # Main can't go, and bad input is refused.
    bad = {"name": "Me", "color": "#ff4d5e", "removed": True, "updatedAt": clock()}
    assert a.post("/api/profiles", headers=ha, json={"profiles": {"main": bad}}).status_code == 400
    assert a.post("/api/profiles", headers=ha, json={"profiles": {"x": {**bad, "removed": False, "color": "red"}}}).status_code == 400
    many = {f"p{i}": {"name": f"P{i}", "color": "#000000", "updatedAt": clock()} for i in range(13)}
    assert a.post("/api/profiles", headers=ha, json={"profiles": many}).status_code == 400


def test_progress_from_before_profiles_is_kept_as_main(tmp_path):
    """A database from before v3 keeps its progress, now under the main profile."""
    import sqlite3
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version VALUES (2);
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, google_sub TEXT, email TEXT, name TEXT, created_at INTEGER);
        INSERT INTO users (id, google_sub, email, name, created_at) VALUES (1, 's', 'a@b', 'A', 1);
        CREATE TABLE progress (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            video_id TEXT NOT NULL, position REAL, duration REAL, watched INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, changed_at INTEGER NOT NULL, PRIMARY KEY (user_id, video_id));
        INSERT INTO progress VALUES (1, 'tt0133093', 12.5, 100, 0, 5, 6);
    """)
    c.commit(); c.close()
    appmod.Database(path)
    appmod.Database(path)  # a second start changes nothing
    c = sqlite3.connect(path)
    assert c.execute("SELECT profile, video_id, position FROM progress").fetchall() == [("main", "tt0133093", 12.5)]
    assert c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == appmod.SCHEMA_VERSION
