"""Reels shared into a watch party: the queue the party's TV plays."""

import pytest

import app as appmod
from test_party import join, start, tok


class FakeInstagram:
    """Stands in for resolve_reel: no requests to Instagram from the tests."""

    def __init__(self):
        self.asked: list[str] = []
        self.refuse: set[str] = set()

    def __call__(self, shortcode):
        self.asked.append(shortcode)
        if shortcode in self.refuse:
            raise appmod.ReelError("Requested content is not available")
        return {"video": f"https://cdn.example/{shortcode}-{len(self.asked)}.mp4", "thumb": f"https://cdn.example/{shortcode}.jpg",
                "author": "someone", "caption": "a cat", "duration": 12.5}


@pytest.fixture
def instagram(monkeypatch):
    fake = FakeInstagram()
    monkeypatch.setattr(appmod, "resolve_reel", fake)
    return fake


def add(client, code, token, url):
    return client.post(f"/api/party/{code}/reels", headers=tok(token), json={"url": url})


@pytest.mark.parametrize("url,shortcode", [
    ("https://www.instagram.com/reel/Chunk8-jurw/?igsh=MWQ1ZGUxMzBkMA==", "Chunk8-jurw"),
    ("Look at this https://instagram.com/reels/CDUMkliABpa lol", "CDUMkliABpa"),
    ("https://www.instagram.com/p/BQ0eAlwhDrw/", "BQ0eAlwhDrw"),
    ("https://www.instagram.com/clippedinandfree/reel/CDUMkliABpa/", "CDUMkliABpa"),
    ("instagram.com/tv/BkfuX9UB-eK", "BkfuX9UB-eK"),
])
def test_reel_links_in_the_shapes_instagram_shares_them(url, shortcode):
    assert appmod.reel_shortcode(url) == shortcode


@pytest.mark.parametrize("text", ["https://www.youtube.com/watch?v=abc", "https://www.instagram.com/someone/", "", None, 42])
def test_other_links_are_not_reels(text):
    assert appmod.reel_shortcode(text) is None


def test_anyone_queues_a_reel_and_everyone_sees_the_queue(client, instagram):
    host = start(client)
    code = host["party"]["code"]
    guest = join(client, code)

    r = add(client, code, guest["token"], "https://www.instagram.com/reel/Chunk8-jurw/?igsh=x")
    assert r.status_code == 200, r.text
    reels = r.json()["reels"]
    assert len(reels) == 1
    assert reels[0]["code"] == "Chunk8-jurw" and reels[0]["name"] == "Dani" and reels[0]["by"] == guest["party"]["you"]
    assert reels[0]["caption"] == "a cat" and reels[0]["duration"] == 12.5
    assert "video" not in reels[0]

    add(client, code, host["token"], "https://www.instagram.com/reel/CDUMkliABpa/")
    seen = client.get(f"/api/party/{code}", headers=tok(host["token"])).json()["reels"]
    assert [x["code"] for x in seen] == ["Chunk8-jurw", "CDUMkliABpa"]


def test_the_same_reel_twice_and_bad_links_are_refused(client, instagram):
    host = start(client)
    code = host["party"]["code"]
    assert add(client, code, host["token"], "https://www.instagram.com/reel/Chunk8-jurw/").status_code == 200
    assert add(client, code, host["token"], "https://instagram.com/reels/Chunk8-jurw").status_code == 409
    assert add(client, code, host["token"], "https://example.com/video.mp4").status_code == 400
    instagram.refuse.add("PrivateOne1")
    r = add(client, code, host["token"], "https://www.instagram.com/reel/PrivateOne1/")
    assert r.status_code == 422
    assert "private" in r.json()["error"]
    # Not in the party: no queueing.
    assert add(client, code, "nope", "https://www.instagram.com/reel/AnotherOne/").status_code == 403


def test_the_screen_playing_it_gets_the_video_and_finishing_takes_it_off(client, instagram):
    host = start(client)
    code = host["party"]["code"]
    tv = join(client, code, name="Living room")
    first = add(client, code, host["token"], "https://www.instagram.com/reel/Chunk8-jurw/").json()["reels"][0]
    add(client, code, host["token"], "https://www.instagram.com/reel/CDUMkliABpa/")

    r = client.get(f"/api/party/{code}/reels/{first['id']}/play", headers=tok(tv["token"]))
    assert r.status_code == 200
    assert r.json()["video"].startswith("https://cdn.example/Chunk8-jurw")
    # Cached: looked up once for the queue and the play.
    assert instagram.asked.count("Chunk8-jurw") == 1
    # A link that stopped working: asked again.
    again = client.get(f"/api/party/{code}/reels/{first['id']}/play?fresh=1", headers=tok(tv["token"])).json()
    assert instagram.asked.count("Chunk8-jurw") == 2 and again["video"] != r.json()["video"]

    after = client.post(f"/api/party/{code}/reels/{first['id']}/remove", headers=tok(tv["token"])).json()
    assert [x["code"] for x in after["reels"]] == ["CDUMkliABpa"]
    # Two TVs both finishing it: the second changes nothing.
    version = after["version"]
    twice = client.post(f"/api/party/{code}/reels/{first['id']}/remove", headers=tok(host["token"])).json()
    assert twice["version"] == version
    assert client.get(f"/api/party/{code}/reels/{first['id']}/play", headers=tok(tv["token"])).status_code == 404


def test_the_queue_has_a_limit(client, instagram):
    host = start(client)
    code = host["party"]["code"]
    guest = join(client, code)
    for i in range(appmod.PARTY_REELS_MAX):
        who = host if i % 2 else guest  # two people, so the per-person rate limit isn't what stops it
        assert add(client, code, who["token"], f"https://www.instagram.com/reel/Reel{i:04d}x/").status_code == 200
    assert add(client, code, host["token"], "https://www.instagram.com/reel/OneTooMany/").status_code in (409, 429)
