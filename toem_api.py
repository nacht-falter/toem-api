import os
import secrets
import sqlite3
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

security = HTTPBearer()
DEVELOPMENT = os.environ.get("DEVELOPMENT", "False").lower() == "true"
DATABASE_PATH = os.getenv("DB_PATH", "data/toem.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

app = FastAPI(
    title="Toem API",
    docs_url="/docs" if DEVELOPMENT else None,
    redoc_url="/redoc" if DEVELOPMENT else None,
    openapi_url="/openapi.json" if DEVELOPMENT else None,
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
            id INTEGER PRIMARY KEY,
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
    return [dict(row) for row in rows]


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
        return dict(row)
    raise HTTPException(status_code=404, detail="Item not found")


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
