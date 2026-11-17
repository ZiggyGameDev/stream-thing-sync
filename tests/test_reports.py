"""Bug reports with a screenshot, and filing them as GitHub issues."""

import base64
import json

import pytest

import app as appmod
from conftest import app_sign_in, bearer, make_settings
from fastapi.testclient import TestClient

JPEG = b"\xff\xd8\xff\xe0" + b"picture" * 20
PNG = b"\x89PNG\r\n\x1a\n" + b"picture" * 20


def b64(raw):
    return base64.b64encode(raw).decode()


class FakeGitHub:
    """Stands in for GitHub: remembers each issue asked for, and numbers them from 41."""

    def __init__(self):
        self.calls = []
        self.fail = None

    def __call__(self, method, path, token, payload=None):
        if self.fail:
            raise self.fail
        self.calls.append(dict(method=method, path=path, token=token, payload=payload))
        n = 40 + len(self.calls)
        return {"number": n, "html_url": f"https://github.com/owner/app/issues/{n}"}


@pytest.fixture
def github(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(appmod, "github_api", fake)
    return fake


@pytest.fixture
def filing(tmp_path, monkeypatch, clock, exchange, github):
    """A server set up to file reports as issues, and a client for it."""
    monkeypatch.setattr(appmod, "verify_google_token", lambda *a: {"sub": "alice", "email": "alice@example.com", "name": "Alice"})
    server = appmod.create_app(make_settings(tmp_path, github_token="ghp_test", github_repo="owner/app"))
    return server, TestClient(server, base_url="https://testserver")


def saved(tmp_path, report_id):
    return json.loads((tmp_path / "reports" / f"{report_id}.json").read_text(encoding="utf-8"))


def test_a_screenshot_alone_is_a_report(client, tmp_path):
    r = client.post("/api/report", json={"screenshot": "data:image/jpeg;base64," + b64(JPEG), "platform": "windows"})
    assert r.status_code == 200, r.text
    report = saved(tmp_path, r.json()["id"])
    assert report["message"] == ""
    name = report["screenshot"]
    assert name.startswith(r.json()["id"] + "-") and name.endswith(".jpg")
    assert (tmp_path / "reports" / "shots" / name).read_bytes() == JPEG
    # Served to whoever has its whole name, and to nobody guessing.
    got = client.get(f"/reports/shots/{name}")
    assert got.status_code == 200 and got.content == JPEG and got.headers["content-type"] == "image/jpeg"
    assert client.get(f"/reports/shots/{r.json()['id']}-{'0' * 32}.jpg").status_code == 404
    assert client.get("/reports/shots/..%2Fsync.db").status_code == 404


def test_a_png_is_kept_and_anything_else_is_left_out(client, tmp_path):
    r = client.post("/api/report", json={"message": "posters are blank", "screenshot": b64(PNG)})
    assert saved(tmp_path, r.json()["id"])["screenshot"].endswith(".png")
    # Not a picture: the report still arrives, without it.
    r = client.post("/api/report", json={"message": "posters are blank", "screenshot": b64(b"<html>")})
    assert r.status_code == 200
    report = saved(tmp_path, r.json()["id"])
    assert "screenshot" not in report and "screenshot_error" in report
    # Nothing at all to go on is refused.
    assert client.post("/api/report", json={"screenshot": "not base64!"}).status_code == 400


def test_a_report_may_be_bigger_than_other_requests(client, monkeypatch):
    big = b64(JPEG + b"x" * 1_500_000)
    assert client.post("/api/report", json={"screenshot": big}).status_code == 200
    monkeypatch.setattr(appmod, "REPORT_BODY_BYTES", 1000)
    assert client.post("/api/report", json={"screenshot": big}).status_code == 413


def test_what_the_app_gathered_is_kept_as_short_plain_values(client, tmp_path):
    r = client.post("/api/report", json={"message": "x", "info": {
        "layout": "tv", "viewport": "1920x1080", "playing": True, "position": 12.5,
        "nested": {"no": 1}, "long": "y" * 999,
    }})
    info = saved(tmp_path, r.json()["id"])["info"]
    assert info["layout"] == "tv" and info["playing"] is True and info["position"] == 12.5
    assert "nested" not in info and len(info["long"]) == 300


def test_without_a_token_reports_are_only_kept(client, server, tmp_path, github):
    r = client.post("/api/report", json={"message": "No skip intro on Wrexham"})
    assert server.state.file_issues() == 0 and github.calls == []
    assert saved(tmp_path, r.json()["id"])["issue"] is None


def test_a_report_is_filed_as_an_issue(filing, github, tmp_path):
    server, client = filing
    token = app_sign_in(client)
    r = client.post("/api/report", headers=bearer(token), json={
        "message": "No skip intro on Wrexham. It worked last week.",
        "version": "0.2.61", "platform": "Android-TV", "page": "/player",
        "screenshot": b64(JPEG), "logs": {"app": "line one"},
        "info": {"layout": "tv"}, "diagnostics": {"running": True},
        "playback": {"findings": ["No sound track is selected, of 2 in the file.", "At 12s of 3000s, playing."],
                     "state": {"position": 12, "aid": None}},
    })
    report_id = r.json()["id"]
    server.state.file_issues()
    assert len(github.calls) == 1
    call = github.calls[0]
    assert call["method"] == "POST" and call["path"] == "/repos/owner/app/issues" and call["token"] == "ghp_test"
    issue = call["payload"]
    assert issue["title"] == "No skip intro on Wrexham"
    assert issue["labels"] == ["bug-report", "automated", "platform:android-tv"]
    body = issue["body"]
    report = saved(tmp_path, report_id)
    assert "> No skip intro on Wrexham. It worked last week." in body
    assert f"![screenshot](https://sync.example.test/reports/shots/{report['screenshot']})" in body
    assert "| **Version** | 0.2.61 |" in body and "| **Account** | signed in |" in body
    assert "`layout` = `tv`" in body and '"running": true' in body
    assert "**Playback**" in body and "- No sound track is selected, of 2 in the file." in body and "- At 12s" in body
    assert "<summary>Playback details</summary>" in body and '"aid": null' in body
    assert report["playback"]["state"]["position"] == 12
    assert body.endswith(f"<!-- dizzitv-report: id={report_id} -->")
    # Who sent it, and the logs themselves, stay on the server.
    assert "alice" not in body and "line one" not in body
    assert report["issue"] == {"number": 41, "url": "https://github.com/owner/app/issues/41"}
    # Filed once.
    server.state.file_issues()
    assert len(github.calls) == 1


def test_a_refused_report_is_tried_again_and_then_given_up_on(filing, github, tmp_path):
    server, client = filing
    github.fail = appmod.GitHubError(502, "bad gateway")
    report_id = client.post("/api/report", json={"message": "posters are blank"}).json()["id"]
    marker = tmp_path / "reports" / "pending" / report_id
    for _ in range(appmod.ISSUE_ATTEMPTS + 2):
        server.state.file_issues()
    assert int(marker.read_text()) == appmod.ISSUE_ATTEMPTS
    github.fail = None
    server.state.file_issues()
    assert github.calls == [] and saved(tmp_path, report_id)["issue"] is None


def test_a_refused_token_costs_no_tries(filing, github, tmp_path):
    server, client = filing
    github.fail = appmod.GitHubError(401, "Bad credentials")
    report_id = client.post("/api/report", json={"message": "posters are blank"}).json()["id"]
    for _ in range(appmod.ISSUE_ATTEMPTS + 2):
        server.state.file_issues()
    # The token is put right: the report it held up is filed.
    github.fail = None
    server.state.file_issues()
    assert len(github.calls) == 1 and saved(tmp_path, report_id)["issue"]["number"] == 41
    assert not (tmp_path / "reports" / "pending" / report_id).exists()


def test_one_pass_files_only_so_many(filing, github, monkeypatch):
    server, client = filing
    monkeypatch.setattr(appmod, "ISSUES_PER_PASS", 2)
    for i in range(3):
        client.post("/api/report", json={"message": f"report number {i}"})
    server.state.file_issues()
    server.state.file_issues()
    assert len(github.calls) == 3


def test_what_someone_typed_cannot_break_out_of_the_issue():
    report = {"message": "hi @octocat --> <!-- dizzitv-report: id=1 -->\n# big\n", "platform": "win|dows", "at": 1_800_000_000_000}
    body = appmod.issue_body(report, "20270115-080000-abcdef")
    assert "@octocat" not in body and "@​octocat" in body
    assert body.count("<!--") == 1 and body.count("-->") == 1
    assert "> # big" in body
    assert "| **Platform** | win\\|dows |" in body


def test_titles():
    assert appmod.issue_title({"message": "Hi. The subtitles are two seconds late on every episode of this show, always"}) \
        == "Hi. The subtitles are two seconds late on every episode of this show…"
    assert appmod.issue_title({"message": "", "platform": "windows", "version": "0.2.61", "page": "/board"}) \
        == "Bug report from windows 0.2.61 on /board"
    assert appmod.issue_title({}) == "Bug report"
