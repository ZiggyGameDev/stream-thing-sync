import hashlib
import json
from pathlib import Path

import pytest

APK_TYPE = "application/vnd.android.package-archive"


@pytest.fixture
def updates(server):
    d = Path(server.state.settings.data_dir) / "updates"
    d.mkdir()
    return d


def test_nothing_published_is_a_clean_404(client):
    r = client.get("/updates/latest.json")
    assert r.status_code == 404 and r.json() == {"error": "no update published"}
    assert client.get("/updates/files/stream-thing-0.2.0-arm64.apk").status_code == 404


def test_manifest_served_uncached(client, updates):
    manifest = {"version": "0.3.0", "notes": "hi", "windows": {"url": "/updates/files/x.exe", "sha256": "ab", "size": 1}}
    (updates / "latest.json").write_text(json.dumps(manifest), encoding="utf-8")
    r = client.get("/updates/latest.json")
    assert r.status_code == 200
    assert r.json() == manifest
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["cache-control"] == "no-cache"
    assert client.head("/updates/latest.json").status_code == 200


def test_corrupt_manifest_is_503(client, updates):
    (updates / "latest.json").write_text("{half", encoding="utf-8")
    r = client.get("/updates/latest.json")
    assert r.status_code == 503 and "error" in r.json()


def test_files_have_the_right_types_and_bytes(client, updates):
    apk = bytes(range(256)) * 400
    (updates / "stream-thing-0.3.0-arm64.apk").write_bytes(apk)
    (updates / "stream-thing-0.3.0-windows.exe").write_bytes(b"MZ" + b"\0" * 1000)

    r = client.get("/updates/files/stream-thing-0.3.0-arm64.apk")
    assert r.status_code == 200
    assert r.headers["content-type"] == APK_TYPE
    assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(apk).hexdigest()
    assert int(r.headers["content-length"]) == len(apk)
    assert "attachment" in r.headers["content-disposition"]

    r = client.get("/updates/files/stream-thing-0.3.0-windows.exe")
    assert r.status_code == 200 and r.headers["content-type"] == "application/octet-stream"
    assert r.content[:2] == b"MZ"


def test_range_requests(client, updates):
    data = b"0123456789" * 1000
    (updates / "a.apk").write_bytes(data)
    r = client.get("/updates/files/a.apk", headers={"Range": "bytes=10-19"})
    assert r.status_code == 206
    assert r.content == data[10:20]
    assert r.headers["content-range"] == f"bytes 10-19/{len(data)}"


@pytest.mark.parametrize("name", [
    "latest.json",          # not a downloadable type
    "notes.txt",
    "..%2Fsync.db",
    "..%5Csync.db.apk",
    ".hidden.apk",
    "a b.apk",
    "missing.apk",
    "x" * 200 + ".apk",
])
def test_bad_or_unknown_names_404(client, updates, name):
    (updates / "notes.txt").write_text("x")
    (updates.parent / "sync.db.apk").write_bytes(b"secret")
    r = client.get(f"/updates/files/{name}")
    assert r.status_code == 404
    assert b"secret" not in r.content


def test_traversal_through_the_path_never_escapes(client, updates):
    (updates.parent / "outside.apk").write_bytes(b"secret")
    for path in ("/updates/files/../outside.apk", "/updates/files/%2e%2e/outside.apk",
                 "/updates/files/..%2Foutside.apk"):
        r = client.get(path)
        assert b"secret" not in r.content
        assert r.status_code == 404


def test_directories_are_not_files(client, updates):
    (updates / "dir.apk").mkdir()
    assert client.get("/updates/files/dir.apk").status_code == 404


def test_updates_are_read_only(client, updates):
    assert client.put("/updates/latest.json", content=b"{}").status_code == 405
    assert client.post("/updates/files/a.apk", content=b"x").status_code == 405
    assert not (updates / "latest.json").exists()
