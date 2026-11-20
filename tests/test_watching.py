"""What is watched, added up from accounts' synced progress for the stats pages."""

import pytest

import app as appmod
from conftest import app_sign_in, bearer, make_settings
from fastapi.testclient import TestClient

STATS = "s" * 32
HOUR = 3_600_000
DAY = 24 * HOUR

CATALOGUE = {
    ("series", "tt0903747"): {"name": "Breaking Bad", "year": 2008, "genres": ["Crime", "Drama"], "country": "United States", "rating": 9.5},
    ("movie", "tt0133093"): {"name": "The Matrix", "year": 1999, "genres": ["Action", "Sci-Fi"], "country": "United States", "rating": 8.7},
    ("series", "tt5875444"): {"name": "Slow Horses", "year": 2022, "genres": ["Drama", "Thriller"], "country": "United Kingdom", "rating": 8.3},
}


@pytest.fixture
def catalogue(monkeypatch):
    asked = []

    def fake(kind, title_id):
        asked.append((kind, title_id))
        return CATALOGUE.get((kind, title_id))

    monkeypatch.setattr(appmod, "fetch_title_meta", fake)
    return asked


@pytest.fixture
def watched(tmp_path, monkeypatch, clock, exchange, catalogue):
    """A server with a stats page and two accounts' worth of viewing."""
    monkeypatch.setattr(appmod, "verify_google_token", lambda cred, aud: {"sub": cred, "email": f"{cred}@example.com", "name": cred})
    server = appmod.create_app(make_settings(tmp_path, stats_token=STATS))
    client = TestClient(server, base_url="https://testserver")
    now = clock()
    alice = client.post("/api/auth/google", json={"id_token": "alice", "device_name": "Android TV · Shield"}).json()["token"]
    bob = client.post("/api/auth/google", json={"id_token": "bob", "device_name": "Windows PC"}).json()["token"]
    client.post("/api/progress", headers=bearer(alice), json={"progress": {
        "tt0903747:1:1": {"position": 2800, "duration": 2800, "watched": True, "updatedAt": now - 2 * HOUR},
        "tt0903747:1:2": {"position": 1400, "duration": 2800, "watched": False, "updatedAt": now - HOUR},
        "tt0133093": {"position": 8160, "duration": 8160, "watched": True, "updatedAt": now - 3 * DAY},
        # Long ago: outside a month, still part of everything.
        "tt5875444:1:1": {"position": 3000, "duration": 3000, "watched": True, "updatedAt": now - 200 * DAY},
    }})
    client.post("/api/progress", headers=bearer(bob), json={"progress": {
        "tt0903747:1:1": {"position": 2800, "duration": 2800, "watched": True, "updatedAt": now - 10 * DAY},
        "kitsu:7442:3": {"position": 600, "duration": 1400, "watched": False, "updatedAt": now - DAY},
        "tt9999999": {"position": 60, "duration": None, "watched": False, "updatedAt": now - DAY},
    }})
    client.post("/api/list", headers=bearer(bob), json={"list": {
        "tt5875444": {"type": "series", "name": "Slow Horses", "poster": None, "addedAt": now - DAY, "updatedAt": now - DAY},
        "tt0133093": {"type": "movie", "name": "The Matrix", "poster": None, "addedAt": now - DAY, "updatedAt": now - DAY},
    }})
    return server, client


def watching(client, days=30):
    r = client.get(f"/api/stats/watching?days={days}", headers=bearer(STATS))
    assert r.status_code == 200, r.text
    return r.json()


def by_id(items):
    return {t["id"]: t for t in items}


def test_an_id_is_a_title_and_a_kind():
    assert appmod.title_of("tt0903747:1:2") == ("tt0903747", "episode")
    assert appmod.title_of("tt0133093") == ("tt0133093", "film")
    assert appmod.title_of("kitsu:7442:3") == ("kitsu:7442", "episode")
    assert appmod.title_of("local-file.mkv") == ("local-file.mkv", "other")


def test_titles_are_added_up_across_accounts(watched):
    server, client = watched
    server.state.lookup_titles()
    got = watching(client)
    titles = by_id(got["titles"])
    bad = titles["tt0903747"]
    assert bad["name"] == "Breaking Bad" and bad["type"] == "series" and bad["year"] == 2008
    assert bad["viewers"] == 2 and bad["plays"] == 3 and bad["finished"] == 2 and bad["episodes"] == 2
    # Two whole episodes and half of one.
    assert bad["hours"] == pytest.approx(2.5 * 2800 / 3600, abs=0.01)
    assert titles["tt0133093"]["name"] == "The Matrix" and titles["tt0133093"]["kind"] == "film"
    # Nothing in the catalogue for it: its id stands in for a name.
    assert titles["tt9999999"]["name"] == "tt9999999"
    # Outside the month.
    assert "tt5875444" not in titles
    assert got["totals"] == {"accounts": 2, "active": 2, "devices": 2, "profiles": 0, "plays": 6, "finished": 3,
                             "hours": got["totals"]["hours"], "titles": 4, "named": 2}
    assert "tt5875444" in by_id(watching(client, days=0)["titles"])
    assert "tt0133093" not in by_id(watching(client, days=2)["titles"])


def test_kinds_genres_years_and_countries(watched):
    server, client = watched
    server.state.lookup_titles()
    got = watching(client)
    kinds = {k["kind"]: k for k in got["kinds"]}
    assert kinds["episode"]["plays"] == 4 and kinds["episode"]["viewers"] == 2
    assert kinds["film"]["plays"] == 2
    genres = {g["genre"]: g for g in got["genres"]}
    assert genres["Drama"]["plays"] == 3 and genres["Drama"]["viewers"] == 2 and genres["Drama"]["titles"] == 1
    assert genres["Sci-Fi"]["plays"] == 1
    assert [d["decade"] for d in got["decades"]] == [1990, 2000]
    assert got["countries"][0]["country"] == "United States" and got["countries"][0]["titles"] == 2
    assert got["ratings"][9] == 1 and got["ratings"][8] == 1


def test_when_and_how_far(watched):
    _, client = watched
    got = watching(client)
    assert sum(sum(row) for row in got["heat"]) == 6
    assert sum(d["plays"] for d in got["daily"]) == 6
    assert max(d["accounts"] for d in got["daily"]) >= 1
    # Three finished, one half way, one 40% in; the one with no length isn't placed.
    assert got["completion"] == [0, 0, 0, 0, 1, 1, 0, 0, 0, 3]


def test_what_is_on_the_way_up(watched):
    _, client = watched
    rising = by_id(watching(client)["rising"])
    # Two plays this week and one the week before.
    assert rising["tt0903747"]["recent"] == 2 and rising["tt0903747"]["before"] == 1
    assert "tt5875444" not in rising


def test_my_list_and_devices(watched):
    server, client = watched
    server.state.lookup_titles()
    got = watching(client)
    listed = by_id(got["list"])
    assert listed["tt5875444"]["name"] == "Slow Horses" and listed["tt5875444"]["adds"] == 1
    # Saved by one account, watched (ever) by another.
    assert listed["tt5875444"]["watched_by"] == 1 and listed["tt0133093"]["watched_by"] == 1
    assert {d["kind"]: d["n"] for d in got["devices"]} == {"Android TV": 1, "Windows PC": 1}


def test_nothing_about_one_person_leaves(watched):
    _, client = watched
    text = client.get("/api/stats/watching?days=0", headers=bearer(STATS)).text
    for private in ("alice", "bob", "example.com", "Shield", "user_id"):
        assert private not in text


def test_titles_are_looked_up_once_and_a_miss_waits(watched, catalogue, clock):
    server, client = watched
    assert server.state.lookup_titles() == 5
    # The show first for an episode's id, the film first for a bare one; the other kind when that misses.
    assert ("series", "tt0903747") in catalogue and ("movie", "tt0133093") in catalogue
    assert ("movie", "tt9999999") in catalogue and ("series", "tt9999999") in catalogue
    assert server.state.lookup_titles() == 0
    clock.advance(8 * 86400)
    asked_before = len(catalogue)
    # Only the ones nothing knew are asked about again.
    assert server.state.lookup_titles() == 2
    assert {i for _, i in catalogue[asked_before:]} == {"tt9999999", "kitsu:7442"}


def test_a_catalogue_that_cannot_be_reached_stops_the_pass(watched, monkeypatch):
    server, client = watched

    def down(kind, title_id):
        raise OSError("no route")

    monkeypatch.setattr(appmod, "fetch_title_meta", down)
    assert server.state.lookup_titles() == 0
    # The page still has its numbers, with ids for names.
    assert by_id(watching(client)["titles"])["tt0903747"]["name"] == "tt0903747"


def test_watching_needs_the_password(watched, client):
    _, counted = watched
    assert counted.get("/api/stats/watching").status_code == 401
    assert counted.get("/api/stats/watching", headers=bearer("x" * 32)).status_code == 401
    # No password set up: no such page.
    assert client.get("/api/stats/watching", headers=bearer(STATS)).status_code == 404
