# stream-thing-sync

A small account and sync server for **stream-thing**, a Stremio-style streaming
app for Windows, Android phones and Android TV. It lets people:

- sign up / sign in with Google from inside the app (no passwords, no email
  verification),
- keep their API keys (TorBox or Real-Debrid, MDBList, aioratings poster key)
  encrypted on the server so a new device picks them up automatically,
- sync watch progress between devices (this replaces Simkl in the app),
- manage their keys and signed-in devices, or delete their account, on the
  website.

Live at <https://sync.thestoreisclosed.co.uk>. Python 3.12, FastAPI, SQLite —
one file (`app.py`) and one page (`static/index.html`).

## API

All JSON. Errors are `{"error": "..."}` with a meaningful status: 400 bad
input, 401 bad/missing token or rejected Google credential, 403 missing CSRF
header, 404, 429 rate-limited, 502 couldn't reach Google, 503 not configured.

### In-app sign-in (returns a device token)

Signing in is also signing up: the first sign-in with a Google account creates it.

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/auth/google` | `{"id_token", "device_name"}` | **Android.** Credential Manager's Google ID token. Its audience may be any ID in `GOOGLE_CLIENT_IDS` (plus `GOOGLE_CLIENT_ID`, always) — Credential Manager tokens carry the *web* client ID |
| POST | `/api/auth/google-code` | `{"code", "code_verifier", "redirect_uri", "device_name"}` | **Windows.** System-browser loopback flow with PKCE against the *desktop* client. The server exchanges the code at `https://oauth2.googleapis.com/token` with `GOOGLE_DESKTOP_CLIENT_ID` + `GOOGLE_DESKTOP_CLIENT_SECRET` and verifies the returned ID token (audience = desktop client). `redirect_uri` must be `http://127.0.0.1:<port>/...` or `http://localhost:<port>/...`; `code_verifier` 43–128 chars. 401 if Google rejects the code, 503 if the desktop secret isn't configured |

Both return `{"token": "<device token>", "account": {"email", "name"}}` and are
rate-limited per client IP (shared budget, 10/minute).

### Device API (`Authorization: Bearer <token>`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/me` | `{"email", "name", "device": {"id", "name"}}` |
| GET | `/api/credentials` | `{"credentials": {...set keys only}, "updated_at": ms \| null}` |
| PUT | `/api/credentials` | `{"credentials": {...}}` merge: string sets, `""`/`null` removes, unknown key → 400, max 512 chars. Returns the GET shape |
| GET | `/api/progress?since=ms` | `{"progress": {"<videoId>": {"position", "duration", "watched", "updatedAt"}}, "now": ms}` |
| POST | `/api/progress` | `{"progress": {"<videoId>": {...}}}` → `{"ok": true, "now": ms}`. Newest `updatedAt` wins (ties go to the incoming write). ≤500 entries, videoId ≤200 printable ASCII chars |
| POST | `/api/logout` | Revokes the calling token |

Credential keys: `debrid_service` (`"torbox"` or `"realdebrid"`), `torbox`
(TorBox API key), `realdebrid` (Real-Debrid API token), `mdblist`, `poster`
(aioratings poster key).

`since` semantics: pass back the `now` from your previous GET/POST. The server
returns rows whose `changed_at` (its own clock when the row was last written)
is `> since` — never compared with the device's `updatedAt` — so a device whose
clock runs behind can't hide updates from the others. `now` is one millisecond
behind the server clock so a write in the same millisecond as a pull isn't
missed; an entry may occasionally come back twice, which is harmless with
newest-wins merging. `updatedAt` decides which write wins; values in the future
are clamped to server time.

### Website API (session cookie; non-GET requests need `X-Requested-With: sync`)

The website is for managing the account; devices sign in from inside the app.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/web/google` | `{"credential": "<Google ID token>"}` (audience: `GOOGLE_CLIENT_ID` only) → sets the session cookie (60 days) |
| GET | `/api/web/me` | `{"email", "name", "picture"}` |
| POST | `/api/web/logout` | |
| GET/PUT | `/api/web/credentials` | Same shapes as the device API |
| GET | `/api/web/devices` | `{"devices": [{"id", "name", "created_at", "last_used_at"}]}` |
| DELETE | `/api/web/devices/{id}` | Signs that device out |
| DELETE | `/api/web/account` | Deletes the user and everything belonging to them |

Pages: `/` (account: keys, devices, sign out, delete), `/privacy`, `/terms`.
`GET /healthz` → `{"ok": true}`.

## Security notes

- API keys are encrypted with Fernet (`SECRET_KEY`) before they touch the
  database and decrypted only when served.
- Device tokens (SHA-256) and session ids (HMAC keyed from `SECRET_KEY`) are
  stored hashed.
- The desktop client secret only ever comes from the environment; the Windows
  app never sees it.
- Tokens, keys, OAuth codes/verifiers and ID tokens are never logged; uvicorn's
  access log is off and the app logs paths without query strings.
- Sign-in endpoints are rate-limited per client IP (`CF-Connecting-IP`), in
  memory.
- The page is served with a nonce-based CSP that only allows Google's GIS
  script.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `GOOGLE_CLIENT_ID` | yes | OAuth **Web** client ID (public): `2461014992-1sq5ug6j943fr7kiflnehv5u2ckk1278.apps.googleusercontent.com`. Website sign-in, and always accepted by `/api/auth/google` |
| `SECRET_KEY` | yes | Fernet key. Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Changing it loses all saved API keys and signs everyone out of the website |
| `GOOGLE_CLIENT_IDS` | no | Comma-separated extra audiences for `/api/auth/google`, e.g. the web and desktop IDs |
| `GOOGLE_DESKTOP_CLIENT_ID` | for Windows | OAuth **Desktop** client ID (public): `2461014992-ikm313d2pkmpe8r4fe20rq88vis4dgha.apps.googleusercontent.com` |
| `GOOGLE_DESKTOP_CLIENT_SECRET` | for Windows | **Secret.** Desktop client secret from Google Cloud Console; `.env` on the server only. Without it `/api/auth/google-code` returns 503 |
| `PUBLIC_URL` | no | Default `https://sync.thestoreisclosed.co.uk`. Cookies are `Secure` when it's https |
| `DATA_DIR` | no | Default `/data`; the database is `$DATA_DIR/sync.db` (WAL mode) |

The server refuses to start without `GOOGLE_CLIENT_ID` and a valid `SECRET_KEY`.
In Google Cloud Console the web OAuth client needs `https://sync.thestoreisclosed.co.uk`
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
cp .env.example .env && nano .env            # set SECRET_KEY and GOOGLE_DESKTOP_CLIENT_SECRET
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
