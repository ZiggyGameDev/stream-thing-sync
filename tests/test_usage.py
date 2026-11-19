"""Anonymous usage counts, live channel viewers, and the stats page."""

import pytest

import app as appmod
from conftest import app_sign_in, bearer, make_settings
from fastapi.testclient import TestClient

STATS = "s" * 32
PASS_A = "a" * 20
PASS_B = "b" * 20
PASS_C = "c" * 20


@pytest.fixture
def ticking(monkeypatch):
    """The server's steady clock, moved by hand."""
    t = [1000.0]
    monkeypatch.setattr(appmod, "monotonic", lambda: t[0])
    return t


@pytest.fixture
def counted(tmp_path, monkeypatch, clock, exchange, ticking):
    """A server with a stats page, and a client for it."""
    monkeypatch.setattr(appmod, "verify_google_token", lambda *a: {"sub": "alice", "email": "alice@example.com", "name": "Alice"})
    server = appmod.create_app(make_settings(tmp_path, stats_token=STATS))
    return server, TestClient(server, base_url="https://testserver")


def stats(client, days=30):
    r = client.get(f"/api/stats?days={days}", headers=bearer(STATS))
    assert r.status_code == 200, r.text
    return r.json()


def totals(client):
    return {(platform, version, key): n for _, platform, version, key, n in stats(client)["rows"]}


def report(client, counts, platform="windows", version="0.3.0", **extra):
    return client.post("/api/usage", json={"platform": platform, "version": version, "counts": counts, **extra})


def watch(client, channel, token, ip="1.1.1.1", **extra):
    return client.post("/api/live/watching", json={"channel": channel, "token": token, **extra},
                       headers={"cf-connecting-ip": ip})


def test_reports_add_up_per_day_platform_and_version(counted):
    _, client = counted
    assert report(client, {"active.day": 1, "open.live": 3, "mins.film": 90}).json() == {"ok": True}
    assert report(client, {"active.day": 1, "open.live": 2}).status_code == 200
    assert report(client, {"active.day": 1}, platform="android-tv").status_code == 200
    got = totals(client)
    assert got[("windows", "0.3.0", "active.day")] == 2
    assert got[("windows", "0.3.0", "open.live")] == 5
    assert got[("windows", "0.3.0", "mins.film")] == 90
    assert got[("android-tv", "0.3.0", "active.day")] == 1
    assert stats(client)["since"] < stats(client)["today"]


def test_unknown_keys_are_dropped_and_counts_are_capped(counted):
    _, client = counted
    r = report(client, {
        "open.live": 10_000,                 # over its limit
        "active.day": 50,                    # a device is one device
        "watched.tt0111161": 1,              # not a name this server keeps
        "open.home": -4, "open.films": "9", "open.shows": True, "open.sport": 0.2,
        "mins.film": 12.9,
    }, platform="toaster", version="<script>")
    assert r.status_code == 200
    assert totals(client) == {
        ("other", "other", "open.live"): 200,
        ("other", "other", "active.day"): 1,
        ("other", "other", "mins.film"): 12,
    }


def test_a_report_without_counts_is_refused(counted):
    _, client = counted
    assert client.post("/api/usage", json={"platform": "windows"}).status_code == 400
    assert client.post("/api/usage", json={"counts": [1, 2]}).status_code == 400
    assert client.post("/api/usage", content=b"x" * 9000).status_code == 413


def test_a_report_stores_nothing_about_who_sent_it(counted, tmp_path):
    server, client = counted
    token = app_sign_in(client)
    r = client.post("/api/usage", json={"platform": "windows", "version": "0.3.0", "counts": {"active.day": 1},
                                        "device": "Galaxy S23", "email": "alice@example.com"},
                    headers={**bearer(token), "cf-connecting-ip": "203.0.113.9"})
    assert r.status_code == 200
    server.state.flush_usage()
    with server.state.db.connect() as conn:
        rows = [tuple(r) for r in conn.execute("SELECT * FROM usage")]
    assert len(rows) == 1 and rows[0][1:] == ("windows", "0.3.0", "active.day", 1)
    assert "alice" not in str(rows) and "203.0.113.9" not in str(rows) and "Galaxy" not in str(rows)


def test_days_are_kept_apart(counted, clock):
    _, client = counted
    report(client, {"active.day": 1})
    clock.advance(86400)
    report(client, {"active.day": 1})
    days = sorted(r[0] for r in stats(client)["rows"])
    assert len(days) == 2 and days[0] < days[1]
    # Only the last day when that is all that's asked for.
    assert [r[0] for r in stats(client, days=1)["rows"]] == [days[1]]


def test_viewers_are_counted_and_one_alone_is_not_said(counted):
    _, client = counted
    first = watch(client, "sitcoms", PASS_A, ip="1.1.1.1").json()
    assert first == {"watching": 0, "every": 60}
    assert client.get("/api/live/viewers").json() == {"viewers": {}, "every": 60}
    assert watch(client, "sitcoms", PASS_B, ip="2.2.2.2").json()["watching"] == 2
    assert watch(client, "crime", PASS_C, ip="3.3.3.3").json()["watching"] == 0
    r = client.get("/api/live/viewers")
    assert r.json() == {"viewers": {"sitcoms": 2}, "every": 60}
    assert "max-age=30" in r.headers["cache-control"]
    # The same pass again is the same viewer.
    assert watch(client, "sitcoms", PASS_A, ip="1.1.1.1").json()["watching"] == 2


def test_a_viewer_gone_quiet_or_leaving_is_dropped(counted, ticking):
    _, client = counted
    watch(client, "sitcoms", PASS_A, ip="1.1.1.1")
    watch(client, "sitcoms", PASS_B, ip="2.2.2.2")
    watch(client, "sitcoms", PASS_C, ip="3.3.3.3")
    assert watch(client, "sitcoms", PASS_C, ip="3.3.3.3", leave=True).json() == {"ok": True}
    assert client.get("/api/live/viewers").json()["viewers"] == {"sitcoms": 2}
    ticking[0] += 100
    assert watch(client, "sitcoms", PASS_A, ip="1.1.1.1").json()["watching"] == 2
    # B has said nothing for two and a half beats.
    ticking[0] += 60
    assert watch(client, "sitcoms", PASS_A, ip="1.1.1.1").json()["watching"] == 0
    assert client.get("/api/live/viewers").json()["viewers"] == {}


def test_one_address_cannot_fill_a_channel(counted):
    _, client = counted
    for i in range(12):
        watch(client, "nature", f"{i:02d}" + "x" * 18, ip="9.9.9.9")
    assert client.get("/api/live/viewers").json()["viewers"] == {"nature": appmod.LIVE_PER_IP}


def test_a_bad_pass_is_refused_and_an_unknown_channel_is_other(counted):
    server, client = counted
    assert watch(client, "sitcoms", "short").status_code == 400
    assert watch(client, "sitcoms", "has spaces in it, no").status_code == 400
    watch(client, "my-own-channel-7", PASS_A, ip="1.1.1.1")
    watch(client, "another one", PASS_B, ip="2.2.2.2")
    assert client.get("/api/live/viewers").json()["viewers"] == {}
    assert stats(client)["watching"]["other"] == 2
    assert not any("my-own" in r[3] or "another" in r[3] for r in stats(client)["rows"])


def test_minutes_and_the_most_at_once_are_kept_per_channel(counted, ticking):
    _, client = counted
    watch(client, "scifi", PASS_A, ip="1.1.1.1")
    watch(client, "scifi", PASS_B, ip="2.2.2.2")
    # Beating early adds no minute.
    ticking[0] += 5
    watch(client, "scifi", PASS_A, ip="1.1.1.1")
    ticking[0] += 60
    watch(client, "scifi", PASS_A, ip="1.1.1.1")
    watch(client, "scifi", PASS_B, ip="2.2.2.2", leave=True)
    got = totals(client)
    assert got[("all", "", "live.mins.scifi")] == 3
    assert got[("all", "", "live.peak.scifi")] == 2
    # A lower count later doesn't bring the peak down.
    ticking[0] += 60
    watch(client, "scifi", PASS_A, ip="1.1.1.1")
    assert totals(client)[("all", "", "live.peak.scifi")] == 2


def test_live_counts_can_be_turned_off(tmp_path, clock, exchange):
    server = appmod.create_app(make_settings(tmp_path, live_every_s=0, stats_token=STATS))
    client = TestClient(server, base_url="https://testserver")
    assert watch(client, "sitcoms", PASS_A).json() == {"watching": 0, "every": 0}
    assert watch(client, "sitcoms", PASS_B, ip="2.2.2.2").json() == {"watching": 0, "every": 0}
    assert client.get("/api/live/viewers").json() == {"viewers": {}, "every": 0}
    assert stats(client)["rows"] == []


def test_the_pace_comes_from_the_environment():
    assert appmod._live_every("") == 60
    assert appmod._live_every("0") == 0
    assert appmod._live_every("5") == 30
    assert appmod._live_every("120") == 120
    assert appmod._live_every("99999") == 900
    assert appmod._live_every("soon") == 60


def test_stats_need_the_password(counted):
    _, client = counted
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers=bearer("s" * 31)).status_code == 401
    assert client.get("/api/stats", headers=bearer(STATS)).status_code == 200
    page = client.get("/stats")
    assert page.status_code == 200 and "Stats password" in page.text
    assert page.headers["cache-control"] == "no-store"


def test_there_is_no_stats_page_without_a_password(client):
    assert client.get("/stats").status_code == 404
    assert client.get("/api/stats", headers=bearer("anything")).status_code == 404


def test_a_short_password_leaves_stats_off(tmp_path, clock, exchange):
    server = appmod.create_app(make_settings(tmp_path, stats_token="hunter2"))
    client = TestClient(server, base_url="https://testserver")
    assert client.get("/stats").status_code == 404
    assert client.get("/api/stats", headers=bearer("hunter2")).status_code == 404


def test_the_pages_say_what_is_counted(client):
    privacy = client.get("/privacy").text
    terms = client.get("/terms").text
    assert "Anonymous usage counts" in privacy and "Anonymous usage counts" in terms
    assert "no analytics" not in privacy
