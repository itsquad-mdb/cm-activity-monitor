import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager, closing
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

DB_PATH = os.environ.get("DB_PATH", "/data/activity.db")
API_KEY = os.environ.get("API_KEY")  # Optional - empty = rely on IP whitelist only

log = logging.getLogger("activity")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                computer TEXT NOT NULL,
                source TEXT,
                event_id INTEGER,
                event_type TEXT,
                user TEXT,
                logon_type INTEGER,
                idle_seconds REAL,
                extra TEXT,
                received_at TEXT DEFAULT (datetime('now')),
                UNIQUE(ts, computer, event_id, event_type, user)
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_computer ON events(computer);
            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            """
        )
        conn.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    log.info("DB initialized at %s (API_KEY=%s)", DB_PATH, "set" if API_KEY else "not set")
    yield


app = FastAPI(title="Activity Monitor", version="0.1.0", lifespan=lifespan)


class Event(BaseModel):
    timestamp: str
    source: Optional[str] = None
    eventId: Optional[int] = None
    eventType: Optional[str] = None
    user: Optional[str] = None
    logonType: Optional[int] = None
    logonTypeName: Optional[str] = None
    idleSeconds: Optional[float] = None
    sessionState: Optional[str] = None
    computer: Optional[str] = None  # may be present on each event too


class EventBatch(BaseModel):
    computer: str
    events: list[Event]


def check_auth(x_api_key: Optional[str]):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/events")
def ingest(batch: EventBatch, x_api_key: Optional[str] = Header(None)):
    check_auth(x_api_key)
    inserted = 0
    dupes = 0
    skipped = 0
    with closing(db()) as conn:
        for e in batch.events:
            if not e.timestamp:
                skipped += 1
                continue
            # Bundle any extra fields not in main columns
            extra = e.model_dump(
                exclude={
                    "timestamp",
                    "source",
                    "eventId",
                    "eventType",
                    "user",
                    "logonType",
                    "idleSeconds",
                    "computer",
                }
            )
            try:
                conn.execute(
                    """INSERT INTO events(ts, computer, source, event_id, event_type,
                                           user, logon_type, idle_seconds, extra)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        e.timestamp,
                        batch.computer,
                        e.source,
                        e.eventId,
                        e.eventType,
                        e.user,
                        e.logonType,
                        e.idleSeconds,
                        json.dumps(extra) if extra else None,
                    ),
                )
                inserted += 1
            except sqlite3.IntegrityError:
                dupes += 1
        conn.commit()
    log.info("ingest computer=%s inserted=%d dupes=%d skipped=%d", batch.computer, inserted, dupes, skipped)
    return {"inserted": inserted, "duplicates": dupes, "skipped": skipped}


@app.get("/v1/events")
def query_events(
    frm: str = Query(alias="from"),
    to: str = Query(...),
    user: Optional[str] = None,
    computer: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    check_auth(x_api_key)
    sql = (
        "SELECT ts AS timestamp, computer, source, event_id AS eventId, event_type AS eventType, "
        "user, logon_type AS logonType, idle_seconds AS idleSeconds, extra "
        "FROM events WHERE ts >= ? AND ts <= ?"
    )
    args: list = [frm, to]
    if user:
        sql += " AND user = ?"
        args.append(user)
    if computer:
        sql += " AND computer = ?"
        args.append(computer)
    sql += " ORDER BY ts"
    with closing(db()) as conn:
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
    return rows


@app.get("/v1/computers")
def list_computers(x_api_key: Optional[str] = Header(None)):
    check_auth(x_api_key)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT computer, COUNT(*) AS events, MIN(ts) AS firstSeen, MAX(ts) AS lastSeen "
            "FROM events GROUP BY computer ORDER BY lastSeen DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/v1/users")
def list_users(x_api_key: Optional[str] = Header(None)):
    check_auth(x_api_key)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT user, COUNT(*) AS events, MIN(ts) AS firstSeen, MAX(ts) AS lastSeen "
            "FROM events WHERE user IS NOT NULL GROUP BY user ORDER BY lastSeen DESC"
        ).fetchall()
    return [dict(r) for r in rows]
