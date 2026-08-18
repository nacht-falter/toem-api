import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from typing import List, Optional

import requests
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

security = HTTPBearer()
DEVELOPMENT = os.environ.get("DEVELOPMENT", "False").lower() == "true"
DATABASE_PATH = os.getenv("DB_PATH", "data/toem.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

# base64("client_id:client_secret"). Lives here so that clients never need
# Spotify credentials: catalog search is the one thing they cannot do
# themselves, since /v1/search rejects unauthenticated requests.
SPOTIFY_USERCREDS = os.getenv("SPOTIFY_USERCREDS")
SPOTIFY_MARKET = os.getenv("SPOTIFY_MARKET", "DE")

# Comma-separated list of origins allowed to call this from a browser.
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

app = FastAPI(
    title="Toem API",
    docs_url="/docs" if DEVELOPMENT else None,
    redoc_url="/redoc" if DEVELOPMENT else None,
    openapi_url="/openapi.json" if DEVELOPMENT else None,
)


if CORS_ORIGINS:
    # Required for any browser frontend on another origin: without this the
    # preflight fails and every request is blocked. Deliberately an explicit
    # allowlist rather than "*", because these endpoints are authenticated.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def verify_admin_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token"
        )
    return token


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE token = ?", (token,))
    row = cur.fetchone()
    if not row:
        # Browser sessions map to the same user_id, so everything downstream is
        # unchanged - they are just independently revocable.
        cur.execute("SELECT user_id FROM sessions WHERE token = ?", (token,))
        row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing token")
    return row[0]


class MusicItem(BaseModel):
    rfid: str
    source: str
    location: str
    title: Optional[str] = None


@app.on_event("startup")
def startup():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS music (
            user_id TEXT NOT NULL,
            rfid TEXT NOT NULL,
            source TEXT NOT NULL,
            location TEXT NOT NULL,
            title TEXT,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, rfid)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sync_meta (
        user_id TEXT PRIMARY KEY,
        last_sync TIMESTAMP
    );
    """)
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS update_last_modified
        AFTER UPDATE ON music
        FOR EACH ROW
        BEGIN
            UPDATE music SET last_modified = CURRENT_TIMESTAMP
            WHERE user_id = OLD.user_id AND rfid = OLD.rfid;
        END;
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            token TEXT NOT NULL
        );
    """)
    # Password login for browsers. Added separately so existing token-only
    # users keep working - a null hash simply means "cannot log in with a
    # password", not "no password required".
    columns = [row[1] for row in cur.execute("PRAGMA table_info(users)")]
    if "password_hash" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

    # Browser sessions are separate tokens for the *same* user, because all
    # data is scoped by user_id: a second user would see a different, empty set
    # of cards. Being separate rows, they can be revoked without touching the
    # long-lived token the players use.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            label TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


@app.get("/music")
def get_music(
    since: Optional[str] = None,
    user_id: str = Depends(verify_token)
):
    conn = get_db()
    cur = conn.cursor()
    if since:
        cur.execute(
            "SELECT * FROM music WHERE user_id = ? AND last_modified > ?", (user_id, since))
    else:
        cur.execute("SELECT * FROM music WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    # Don't return user_id
    return [{k: v for k, v in dict(row).items() if k != "user_id"} for row in rows]


@app.get("/music/{rfid}")
def get_music_item(
    rfid: str,
    user_id: str = Depends(verify_token)
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM music WHERE user_id = ? AND rfid = ?", (user_id, rfid))
    row = cur.fetchone()
    conn.close()
    if row:
        return {k: v for k, v in dict(row).items() if k != "user_id"}
    raise HTTPException(status_code=404, detail="Item not found")


@app.post("/music/sync")
def sync_music(
    items: List[MusicItem],
    user_id: str = Depends(verify_token)
):
    conn = get_db()
    cur = conn.cursor()
    for item in items:
        cur.execute("""
            INSERT INTO music (user_id, rfid, source, location, title)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, rfid) DO UPDATE SET
                source = excluded.source,
                location = excluded.location,
                title = excluded.title;
        """, (user_id, item.rfid, item.source, item.location, item.title))

    cur.execute("""
        INSERT INTO sync_meta (user_id, last_sync)
        VALUES (?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            last_sync = CURRENT_TIMESTAMP;
    """, (user_id,))

    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/music/upsert")
def upsert_music(
    item: MusicItem,
    user_id: str = Depends(verify_token)
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM music WHERE user_id = ? AND rfid = ?",
                (user_id, item.rfid))
    exists = cur.fetchone() is not None

    cur.execute("""
        INSERT INTO music (user_id, rfid, source, location, title)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, rfid) DO UPDATE SET
            source = excluded.source,
            location = excluded.location,
            title = excluded.title;
    """, (user_id, item.rfid, item.source, item.location, item.title))
    conn.commit()
    conn.close()

    return {
        "status": "updated" if exists else "inserted",
        "rfid": item.rfid
    }


@app.delete("/music/{rfid}")
def delete_music_item(
    rfid: str,
    user_id: str = Depends(verify_token)
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM music WHERE user_id = ? AND rfid = ?",
                (user_id, rfid))
    conn.commit()
    conn.close()
    return {"status": "deleted"}


class UserCreate(BaseModel):
    user_id: str


@app.post("/users/add", dependencies=[Security(verify_admin_token)])
def add_user(user: UserCreate):
    conn = get_db()
    cur = conn.cursor()
    token = secrets.token_urlsafe(32)

    cur.execute("SELECT 1 FROM users WHERE user_id = ?", (user.user_id,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists")

    cur.execute(
        "INSERT INTO users (user_id, token) VALUES (?, ?)",
        (user.user_id, token)
    )
    conn.commit()
    conn.close()
    return {"status": "user added", "user_id": user.user_id, "token": token}


# --- Spotify catalog search -------------------------------------------------

_spotify_token = {"value": None, "expires_at": 0}


def spotify_app_token():
    """An app-only Spotify token, cached until shortly before it expires

    client_credentials covers catalog lookups and needs no user authorization,
    so this keeps working even when a player's own refresh token has expired.
    Cached because the token lasts an hour and a search per token request would
    double every round trip.
    """
    if not SPOTIFY_USERCREDS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Spotify search is not configured on this server")

    if _spotify_token["value"] and time.time() < _spotify_token["expires_at"]:
        return _spotify_token["value"]

    response = requests.post(
        "https://accounts.spotify.com/api/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {SPOTIFY_USERCREDS}"},
        timeout=10,
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Spotify rejected the credentials: HTTP {response.status_code}")

    payload = response.json()
    _spotify_token["value"] = payload["access_token"]
    _spotify_token["expires_at"] = time.time() + payload.get("expires_in", 3600) - 60
    return _spotify_token["value"]


PLAYLIST_URL_RE = re.compile(
    r"open\.spotify\.com/(?:intl-[a-z]{2}/)?playlist/([A-Za-z0-9]+)")


def playlist_id_from(text):
    """The playlist id in a Spotify link or URI, or None

    Mirrors normalize_spotify_location in the player's register_rfid.py, so
    the same things a user can paste there work here too.
    """
    text = (text or "").strip()
    match = PLAYLIST_URL_RE.search(text)
    if match:
        return match.group(1)
    parts = text.split(":")
    if len(parts) >= 3 and parts[0] == "spotify" and parts[1] == "playlist":
        return parts[2]
    return None


@app.get("/spotify/playlist")
def spotify_playlist(
    url: str,
    user_id: str = Depends(verify_token),
):
    """Resolve a playlist into the episodes a series card would play

    A series card points at a playlist of whole albums, one per episode. The
    grouping here - runs of consecutive tracks sharing an album - must match
    SpotifySeriesPlayer._fetch_episodes in the player, so what is shown before
    saving is what the device will actually play.
    """
    playlist_id = playlist_id_from(url)
    if not playlist_id:
        raise HTTPException(
            status_code=400,
            detail="That is not a Spotify playlist link")

    headers = {"Authorization": "Bearer " + spotify_app_token()}

    meta = requests.get(
        f"https://api.spotify.com/v1/playlists/{playlist_id}",
        params={"fields": "name"}, headers=headers, timeout=10)
    if meta.status_code == 404:
        # Spotify answers 404 rather than 403 for a playlist the caller may
        # not see, so "missing" and "private" are indistinguishable here. This
        # server holds app-only credentials, which see public playlists only,
        # and a private playlist is much the likelier cause of the two.
        raise HTTPException(
            status_code=404,
            detail="Could not read that playlist. It must be public: this "
                   "server can only see public playlists, and so can any "
                   "player using a different Spotify account. Set the "
                   "playlist to public in Spotify and try again.")
    if meta.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Spotify rejected the playlist lookup: HTTP {meta.status_code}")

    episodes = []
    params = {"limit": 50, "offset": 0, "market": SPOTIFY_MARKET}
    while True:
        page = requests.get(
            f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
            params=params, headers=headers, timeout=10)
        if page.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Reading the playlist failed: HTTP {page.status_code}")
        body = page.json()

        for entry in body.get("items", []):
            album = ((entry.get("track") or {}).get("album") or {})
            uri = album.get("uri")
            if not uri:
                # Removed tracks, local files and podcast episodes.
                continue
            if not episodes or episodes[-1]["uri"] != uri:
                episodes.append({
                    "uri": uri,
                    "name": album.get("name"),
                    "image": (album.get("images") or [{}])[-1].get("url"),
                    "tracks": 0,
                })
            episodes[-1]["tracks"] += 1

        if not body.get("next"):
            break
        params["offset"] += params["limit"]

    return {
        "uri": f"spotify:playlist:{playlist_id}",
        "name": meta.json().get("name"),
        "episodes": episodes,
    }


@app.get("/spotify/search")
def spotify_search(
    q: str,
    limit: int = 8,
    user_id: str = Depends(verify_token),
):
    """Search the Spotify catalog for albums

    Authenticated like everything else, so this is not an open proxy.
    Returns only what a card needs, so clients do not have to know the shape of
    Spotify's responses.
    """
    if not q.strip():
        raise HTTPException(status_code=400, detail="q must not be empty")

    limit = max(1, min(limit, 20))

    response = requests.get(
        "https://api.spotify.com/v1/search",
        params={"q": q, "type": "album", "limit": limit,
                "market": SPOTIFY_MARKET},
        headers={"Authorization": "Bearer " + spotify_app_token()},
        timeout=10,
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Spotify search failed: HTTP {response.status_code}")

    albums = response.json().get("albums", {}).get("items", [])
    return [
        {
            "uri": album["uri"],
            "name": album.get("name"),
            "artists": ", ".join(a["name"] for a in album.get("artists", [])),
            # Matches how the existing cards are titled.
            "title": ", ".join(a["name"] for a in album.get("artists", []))
                     + " - " + album.get("name", "")
                     if album.get("artists") else album.get("name", ""),
            "total_tracks": album.get("total_tracks"),
            "release_date": album.get("release_date"),
            "image": (album.get("images") or [{}])[-1].get("url"),
        }
        for album in albums
    ]


# --- password login ---------------------------------------------------------

# PBKDF2 via the standard library: no extra dependency, and adequate here. The
# iteration count is stored with the hash so it can be raised later without
# invalidating existing passwords.
PBKDF2_ITERATIONS = 600_000
# Failed logins are counted per user, within a moving time window. The window
# matters: an unbounded counter that only cleared on a *successful* login was a
# denial of service, because the check runs before verification - ten wrong
# guesses locked the account out until the process restarted, and anyone who
# knew a username could do it deliberately.
_login_failures = {}
MAX_LOGIN_FAILURES = 10
LOGIN_FAILURE_WINDOW = 900  # seconds


def _recent_failures(user_id):
    """Failure timestamps still inside the window, pruning anything older."""
    now = time.time()
    recent = [t for t in _login_failures.get(user_id, ())
              if now - t < LOGIN_FAILURE_WINDOW]
    if recent:
        _login_failures[user_id] = recent
    else:
        _login_failures.pop(user_id, None)
    return recent


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    except (ValueError, AttributeError):
        return False
    # Constant time: a timing difference here would leak the hash byte by byte.
    return hmac.compare_digest(digest.hex(), digest_hex)


# Precomputed once at import so the unknown-user path costs exactly one
# verification, the same as a wrong password.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


class LoginRequest(BaseModel):
    user_id: str
    password: str
    label: Optional[str] = None


class SetPasswordRequest(BaseModel):
    user_id: str
    password: str


@app.post("/login")
def login(request: LoginRequest):
    """Exchange a password for a session token

    Lets a browser sign in with something a password manager can fill, rather
    than a long opaque token typed by hand. The session token is separate from
    the user's long-lived token, so it can be revoked without reconfiguring
    every player.
    """
    recent = _recent_failures(request.user_id)
    if len(recent) >= MAX_LOGIN_FAILURES:
        retry_in = int(LOGIN_FAILURE_WINDOW - (time.time() - recent[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {retry_in}s.",
            headers={"Retry-After": str(retry_in)})

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE user_id = ?", (request.user_id,))
    row = cur.fetchone()

    # Verify against a fixed dummy hash when the user is unknown or has no
    # password, so that case costs the same as a wrong password and the two
    # cannot be told apart by timing. The dummy is precomputed: hashing one
    # here would make the unknown-user path twice as slow, which is the same
    # leak in the other direction.
    stored = row["password_hash"] if row and row["password_hash"] else None
    if stored:
        ok = verify_password(request.password, stored)
    else:
        verify_password(request.password, _DUMMY_HASH)
        ok = False

    if not ok:
        conn.close()
        _login_failures.setdefault(request.user_id, []).append(time.time())
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")

    _login_failures.pop(request.user_id, None)
    session_token = secrets.token_urlsafe(32)
    cur.execute("INSERT INTO sessions (token, user_id, label) VALUES (?, ?, ?)",
                (session_token, request.user_id, request.label or "web"))
    conn.commit()
    conn.close()
    return {"token": session_token, "user_id": request.user_id}


@app.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Revoke the session token presented. A user token is left alone."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/users/password", dependencies=[Security(verify_admin_token)])
def set_password(request: SetPasswordRequest):
    """Set or change a user's password. Admin only."""
    if len(request.password) < 12:
        raise HTTPException(status_code=400,
                            detail="Password must be at least 12 characters")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE user_id = ?",
                (hash_password(request.password), request.user_id))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="No such user")
    conn.commit()
    conn.close()
    return {"status": "ok", "user_id": request.user_id}
