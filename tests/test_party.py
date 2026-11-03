"""Watch together (/api/party) and problem reports (/api/report)."""

import json

import app as appmod
from conftest import app_sign_in, bearer

MEDIA = {"videoId": "tt14674086:1:10", "type": "series", "title": "Welcome to Wrexham · S1E10"}


def start(client, name="Ziggy", **extra):
    r = client.post("/api/party", json={"name": name, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def join(client, code, name="Dani"):
    r = client.post(f"/api/party/{code}/join", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()


def tok(t):
    return {"x-party-token": t}


def test_start_and_join_with_a_code(client):
    host = start(client, media=MEDIA)
    code = host["party"]["code"]
    assert len(code) == 6 and code.isalnum() and code.isupper()
    assert host["party"]["media"]["videoId"] == MEDIA["videoId"]

    # The code works in any case and with stray spaces.
    guest = join(client, f" {code.lower()} ")
    names = [m["name"] for m in guest["party"]["members"]]
    assert names == ["Ziggy", "Dani"]
    assert guest["party"]["host"] == host["party"]["you"]
    assert guest["party"]["media"]["title"].startswith("Welcome")


def test_a_wrong_code_or_token_is_refused(client):
    host = start(client)
    assert client.post("/api/party/ZZZZZZ/join", json={"name": "x"}).status_code == 404
    code = host["party"]["code"]
    assert client.get(f"/api/party/{code}").status_code == 403
    assert client.get(f"/api/party/{code}", headers=tok("nope")).status_code == 403
    assert client.get(f"/api/party/{code}", headers=tok(host["token"])).status_code == 200


def test_only_the_host_picks_what_to_watch_but_anyone_can_pause(client):
    host = start(client, media=MEDIA)
    code = host["party"]["code"]
    guest = join(client, code)

    r = client.post(f"/api/party/{code}/state", headers=tok(guest["token"]),
                    json={"media": {"videoId": "tt0903747:1:1", "type": "series"}})
    assert r.status_code == 403

    r = client.post(f"/api/party/{code}/state", headers=tok(guest["token"]),
                    json={"playback": {"paused": True, "position": 61.5}})
    assert r.status_code == 200
    pb = r.json()["playback"]
    assert pb["paused"] is True and pb["position"] == 61.5 and pb["by"] == guest["party"]["you"]

    # The host switching episode clears the old position.
    r = client.post(f"/api/party/{code}/state", headers=tok(host["token"]),
                    json={"media": {"videoId": "tt14674086:1:11", "type": "series"}})
    assert r.status_code == 200
    state = client.get(f"/api/party/{code}", headers=tok(guest["token"])).json()
    assert state["media"]["videoId"] == "tt14674086:1:11"
    assert state["playback"] is None

    # Browsing the catalogue: the party stays, with nothing playing.
    r = client.post(f"/api/party/{code}/state", headers=tok(host["token"]), json={"media": None})
    assert r.status_code == 200 and r.json()["media"] is None


def test_version_moves_on_every_change(client):
    host = start(client)
    code = host["party"]["code"]
    v0 = host["party"]["version"]
    join(client, code)
    v1 = client.get(f"/api/party/{code}", headers=tok(host["token"])).json()["version"]
    assert v1 > v0
    client.post(f"/api/party/{code}/state", headers=tok(host["token"]), json={"playback": {"paused": False, "position": 3}})
    assert client.get(f"/api/party/{code}", headers=tok(host["token"])).json()["version"] > v1


def test_host_leaving_hands_over_and_the_last_one_out_ends_it(client):
    host = start(client)
    code = host["party"]["code"]
    guest = join(client, code)
    assert client.post(f"/api/party/{code}/leave", headers=tok(host["token"])).status_code == 200
    state = client.get(f"/api/party/{code}", headers=tok(guest["token"])).json()
    assert state["host"] == guest["party"]["you"]
    assert [m["name"] for m in state["members"]] == ["Dani"]

    client.post(f"/api/party/{code}/leave", headers=tok(guest["token"]))
    assert client.post(f"/api/party/{code}/join", json={"name": "x"}).status_code == 404


def test_quiet_members_drop_out(client, monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(appmod, "monotonic", lambda: t[0])
    host = start(client)
    code = host["party"]["code"]
    guest = join(client, code)
    t[0] += 30
    client.get(f"/api/party/{code}", headers=tok(guest["token"]))  # the guest keeps polling
    t[0] += 45  # the host hasn't polled for 75 s
    state = client.get(f"/api/party/{code}", headers=tok(guest["token"])).json()
    assert [m["name"] for m in state["members"]] == ["Dani"]
    assert state["host"] == guest["party"]["you"]


def test_bad_media_is_refused(client):
    r = client.post("/api/party", json={"name": "x", "media": {"videoId": "has space", "type": "series"}})
    assert r.status_code == 400


def test_a_report_is_kept_as_a_file(client, server, tmp_path):
    token = app_sign_in(client)
    r = client.post("/api/report", headers=bearer(token), json={
        "message": "No skip intro on Wrexham",
        "version": "0.2.28-dev.1",
        "platform": "windows",
        "logs": {"app": "line one\nline two"},
        "diagnostics": {"running": True},
    })
    assert r.status_code == 200, r.text
    report_id = r.json()["id"]
    saved = json.loads((tmp_path / "reports" / f"{report_id}.json").read_text(encoding="utf-8"))
    assert saved["message"] == "No skip intro on Wrexham"
    assert saved["logs"]["app"].startswith("line one")
    assert saved["account"]["email"] == "alice@example.com"


def test_a_report_needs_words_and_is_rate_limited(client):
    assert client.post("/api/report", json={"message": "  "}).status_code == 400
    codes = [client.post("/api/report", json={"message": f"report {i}"}).status_code for i in range(8)]
    # The refused one above counted too: six an hour, whatever they were.
    assert codes[:5] == [200] * 5 and codes[-1] == 429
