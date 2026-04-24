import json
import logging
import os
import sqlite3
from collections import defaultdict
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
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


def normalize_user(name):
    if name is None:
        return None
    s = str(name).strip()
    return s.lower() if s else None


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
        # Backfill: normalise any legacy user values to lowercase
        conn.execute(
            "UPDATE events SET user = LOWER(TRIM(user)) "
            "WHERE user IS NOT NULL AND user != LOWER(TRIM(user))"
        )
        conn.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    log.info("DB initialized at %s (API_KEY=%s)", DB_PATH, "set" if API_KEY else "not set")
    yield


app = FastAPI(title="Activity Monitor", version="0.1.0", lifespan=lifespan)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


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
                        normalize_user(e.user),
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
        args.append(normalize_user(user))
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


@app.delete("/v1/events")
def delete_events(
    computer: Optional[str] = None,
    user: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """Hard-delete events matching computer and/or user filter. At least one required."""
    check_auth(x_api_key)
    if not computer and not user:
        raise HTTPException(status_code=400, detail="Must specify at least one of: computer, user")
    sql = "DELETE FROM events WHERE 1=1"
    args: list = []
    if computer:
        sql += " AND computer = ?"
        args.append(computer)
    if user:
        sql += " AND user = ?"
        args.append(normalize_user(user))
    with closing(db()) as conn:
        cur = conn.execute(sql, args)
        conn.commit()
        deleted = cur.rowcount
    log.info("delete computer=%s user=%s deleted=%d", computer, user, deleted)
    return {"deleted": deleted}


@app.get("/v1/users")
def list_users(x_api_key: Optional[str] = Header(None)):
    check_auth(x_api_key)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT user, COUNT(*) AS events, MIN(ts) AS firstSeen, MAX(ts) AS lastSeen "
            "FROM events WHERE user IS NOT NULL GROUP BY user ORDER BY lastSeen DESC"
        ).fetchall()
    return [dict(r) for r in rows]


ARRIVAL_TYPES = {"Logon", "Unlock", "Resume", "Heartbeat"}
DEPART_TYPES = {"Logoff", "Lock", "Sleep"}
PRESENCE_TYPES = ARRIVAL_TYPES | DEPART_TYPES


def _parse_iso(s):
    # Accept trailing Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _local_date(dt):
    # Keep the day-boundary based on the event's own offset (UK/local timezone)
    return dt.date().isoformat()


@app.get("/v1/summary")
def get_summary(
    frm: str = Query(alias="from"),
    to: str = Query(...),
    x_api_key: Optional[str] = Header(None),
):
    """Per-user-per-day rollup: firstArrival, lastActivity, span, locked, active, machines."""
    check_auth(x_api_key)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT ts, computer, event_type, user FROM events "
            "WHERE ts >= ? AND ts <= ? AND user IS NOT NULL "
            "AND event_type IN ('Logon','Logoff','Lock','Unlock','Sleep','Resume','Heartbeat') "
            "ORDER BY ts",
            (frm, to),
        ).fetchall()

    buckets = defaultdict(list)  # (user, date) -> list of (dt, event_type, computer)
    for r in rows:
        try:
            dt = _parse_iso(r["ts"])
        except Exception:
            continue
        key = (r["user"], _local_date(dt))
        buckets[key].append((dt, r["event_type"], r["computer"]))

    results = []
    for (user, date), dayev in buckets.items():
        dayev.sort(key=lambda x: x[0])
        arrivals = [x for x in dayev if x[1] in ARRIVAL_TYPES]
        first_arrival = arrivals[0][0] if arrivals else None
        last_activity = dayev[-1][0] if dayev else None

        # Lock-span accounting: walk events, pair Lock/Sleep -> Unlock/Resume/Logon
        locked_min = 0.0
        lock_start = None
        for dt, et, _ in dayev:
            if et in ("Lock", "Sleep") and lock_start is None:
                lock_start = dt
            elif et in ("Unlock", "Resume", "Logon") and lock_start:
                locked_min += (dt - lock_start).total_seconds() / 60.0
                lock_start = None

        span_min = 0.0
        if first_arrival and last_activity:
            span_min = (last_activity - first_arrival).total_seconds() / 60.0
        active_min = max(0.0, span_min - locked_min)

        machines = sorted({x[2] for x in dayev if x[2]})
        results.append({
            "user": user,
            "date": date,
            "firstArrival": first_arrival.strftime("%H:%M:%S") if first_arrival else None,
            "lastActivity": last_activity.strftime("%H:%M:%S") if last_activity else None,
            "spanMinutes": int(span_min),
            "lockedMinutes": int(locked_min),
            "activeMinutes": int(active_min),
            "machines": machines,
            "eventCount": len(dayev),
        })
    results.sort(key=lambda r: (r["user"], r["date"]))
    return results


@app.get("/v1/status")
def get_status(x_api_key: Optional[str] = Header(None)):
    """Current presence state per user, based on most-recent event."""
    check_auth(x_api_key)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT user, ts, event_type, computer, idle_seconds FROM events e1 "
            "WHERE user IS NOT NULL AND ts = ("
            "  SELECT MAX(ts) FROM events e2 WHERE e2.user = e1.user"
            ") ORDER BY user"
        ).fetchall()

    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        try:
            last_dt = _parse_iso(r["ts"])
        except Exception:
            continue
        age_min = (now - last_dt.astimezone(timezone.utc)).total_seconds() / 60.0
        et = r["event_type"]
        if et in ("Lock", "Sleep"):
            state = "locked"
        elif et in ("Logoff",):
            state = "offline"
        elif age_min > 15:
            state = "stale"  # no heartbeat in 15 min
        elif et == "Heartbeat":
            state = "active" if (r["idle_seconds"] or 0) < 60 else "idle"
        else:
            state = "active"
        out.append({
            "user": r["user"],
            "lastEvent": et,
            "lastEventAt": r["ts"],
            "lastComputer": r["computer"],
            "idleSeconds": r["idle_seconds"],
            "ageMinutes": round(age_min, 1),
            "state": state,
        })
    return out


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
