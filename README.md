# stream-thing-sync

A small account and sync server for **stream-thing**, a Stremio-style streaming
app for Windows, Android phones and Android TV. It lets people:

- sign in with Google (no passwords, no email verification),
- keep their API keys (TorBox, MDBList, aioratings poster key) encrypted on the
  server so a new device picks them up automatically,
- sync watch progress between devices (this replaces Simkl in the app),
- sign in devices that can't do Google sign-in themselves (TVs) with a short
  code entered on the website from a phone.

Live at <https://sync.thestoreisclosed.co.uk>. Python 3.12, FastAPI, SQLite —
one file (`app.py`) and one page (`static/index.html`).

## API

All JSON. Errors are `{"error": "..."}` with a meaningful status: 400 bad
input, 401 bad/missing token or session, 403 missing CSRF header, 404, 410
expired code, 429 rate-limited.

### Device sign-in by code

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/link/start` | `{"device_name"}` | `{"code": "ABCD-2345", "device_secret", "verify_url", "expires_in": 600, "interval": 5}` |
| POST | `/api/link/poll` | `{"device_secret"}` | `{"status": "pending"}`, then once `{"status": "approved", "token", "account": {"email", "name"}}`; 410 when expired/unknown/consumed; 429 if polled faster than ~2s |

Codes are 8 characters from `ABCDEFGHJKMNPQRSTUVWXYZ23456789` (no 0/O/1/I/L),
shown as `XXXX-XXXX`, accepted case- and dash-insensitively, valid 10 minutes.
The user opens `/link` (or `/link?code=...`), signs in with Google and enters
the code.

### Device API (`Authorization: Bearer <token>`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/me` | `{"email", "name", "device": {"id", "name"}}` |
| GET | `/api/credentials` | `{"credentials": {"torbox"?, "mdblist"?, "poster"?}, "updated_at": ms \| null}` |
| PUT | `/api/credentials` | `{"credentials": {...}}` merge: string sets, `""`/`null` removes, unknown key → 400, max 512 chars. Returns the GET shape |
| GET | `/api/progress?since=ms` | `{"progress": {"<videoId>": {"position", "duration", "watched", "updatedAt"}}, "now": ms}` |
| POST | `/api/progress` | `{"progress": {"<videoId>": {...}}}` → `{"ok": true, "now": ms}`. Newest `updatedAt` wins (ties go to the incoming write). ≤500 entries, videoId ≤200 printable ASCII chars |
| POST | `/api/logout` | Revokes the calling token |

`since` semantics: pass back the `now` from your previous GET/POST. The server
returns rows whose `changed_at` (its own clock when the row was last written)
is `> since` — never compared with the device's `updatedAt` — so a device whose
clock runs behind can't hide updates from the others. `now` is one millisecond
behind the server clock so a write in the same millisecond as a pull isn't
missed; an entry may occasionally come back twice, which is harmless with
newest-wins merging. `updatedAt` decides which write wins; values in the future
are clamped to server time.

### Website API (session cookie; non-GET requests need `X-Requested-With: sync`)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/web/google` | `{"credential": "<Google ID token>"}` → sets the session cookie (60 days) |
| GET | `/api/web/me` | `{"email", "name", "picture"}` |
| POST | `/api/web/logout` | |
| GET/PUT | `/api/web/credentials` | Same shapes as the device API |
| GET | `/api/web/devices` | `{"devices": [{"id", "name", "created_at", "last_used_at"}]}` |
| DELETE | `/api/web/devices/{id}` | Signs that device out |
| GET | `/api/web/link/lookup?code=` | `{"device_name", "expires_in"}` — lets the page confirm the device before approving |
| POST | `/api/web/link/approve` | `{"code"}` → `{"ok": true, "device_name"}`; 404 if no such pending code |
| DELETE | `/api/web/account` | Deletes the user and everything belonging to them |

Pages: `/` (account: keys, devices, sign out, delete), `/link`, `/privacy`,
`/terms`. `GET /healthz` → `{"ok": true}`.

## Security notes

- API keys are encrypted with Fernet (`SECRET_KEY`) before they touch the
  database and decrypted only when served.
- Device tokens (SHA-256) and session ids (HMAC keyed from `SECRET_KEY`) are
  stored hashed; link device-secrets are stored hashed too.
- Tokens, keys, codes and ID tokens are never logged; uvicorn's access log is
  off and the app logs paths without query strings.
- `/api/web/google`, `/api/link/start` and code lookup/approve are rate-limited
  per client IP (`CF-Connecting-IP`), in memory.
- The page is served with a nonce-based CSP that only allows Google's GIS
  script.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `GOOGLE_CLIENT_ID` | yes | OAuth Web client ID (public): `2461014992-1sq5ug6j943fr7kiflnehv5u2ckk1278.apps.googleusercontent.com` |
| `SECRET_KEY` | yes | Fernet key. Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Changing it loses all saved API keys and signs everyone out of the website |
| `PUBLIC_URL` | no | Default `https://sync.thestoreisclosed.co.uk`. Used for `verify_url`; cookies are `Secure` when it's https |
| `DATA_DIR` | no | Default `/data`; the database is `$DATA_DIR/sync.db` (WAL mode) |

The server refuses to start without `GOOGLE_CLIENT_ID` and a valid `SECRET_KEY`.
In Google Cloud Console the OAuth client needs `https://sync.thestoreisclosed.co.uk`
(and `http://localhost:8095` for local testing) under *Authorized JavaScript origins*.

## Run locally

```powershell
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
$env:GOOGLE_CLIENT_ID = "2461014992-1sq5ug6j943fr7kiflnehv5u2ckk1278.apps.googleusercontent.com"
$env:SECRET_KEY = (.venv\Scripts\python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
$env:PUBLIC_URL = "http://localhost:8095"
$env:DATA_DIR = "./data"
.venv\Scripts\uvicorn app:app --port 8095
```

Tests: `.venv\Scripts\python -m pytest -q` (Google verification is faked).

## Deployment (cctv)

Runs on the Debian box `cctv` beside cctv and buildbox, as its own compose
project: `server` (this app) and `cloudflared` (its own tunnel). No host port is
published publicly; the tunnel reaches `server:8095` over the compose network,
and `127.0.0.1:8095` is exposed on the box for health checks.

First-time setup on the box:

```sh
git clone https://github.com/ZiggyGameDev/stream-thing-sync.git ~/stream-thing-sync
cd ~/stream-thing-sync
cp .env.example .env && nano .env            # set SECRET_KEY
sudo mkdir -p /mnt/data/stream-thing-sync && sudo chown 1000:1000 /mnt/data/stream-thing-sync

# Tunnel (CLI-managed, nothing to click in the dashboard)
cloudflared tunnel create streamsync
mkdir -p ~/.cloudflared/streamsync
mv ~/.cloudflared/<TUNNEL-UUID>.json ~/.cloudflared/streamsync/
cp cloudflared/config.example.yml ~/.cloudflared/streamsync/config.yml   # fill in the UUID
cloudflared tunnel route dns streamsync sync.thestoreisclosed.co.uk

docker compose up -d --build
curl http://127.0.0.1:8095/healthz
```

Make sure the credentials JSON is readable by the cloudflared container's user
(e.g. `chmod 644`, the directory itself is mounted read-only).

After that, deploy from Windows with `scripts/deploy.ps1`: it pushes `main` to
GitHub, then on the box runs `git fetch && git reset --hard origin/main &&
docker compose up -d --build` and checks `/healthz`.

Backups: the whole state is `/mnt/data/stream-thing-sync/sync.db` (plus `-wal`);
`sqlite3 sync.db ".backup out.db"` gives a consistent copy. Keep `SECRET_KEY`
with it, or the saved API keys can't be decrypted.

## License

MIT — see [LICENSE](LICENSE).
