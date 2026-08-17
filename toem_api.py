import os
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
