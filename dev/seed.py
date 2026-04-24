"""Seed the local dev DB with a realistic team so both dashboard views render.

Usage (from repo root):
    python dev/seed.py                 # wipes $DB_PATH (default ./dev.db) and seeds today
    python dev/seed.py --keep          # seed without wiping existing events
    DB_PATH=./other.db python dev/seed.py

All timestamps are anchored to "today" in local time, so re-running the seed
always produces a populated today's roster regardless of the calendar date.
"""
import argparse
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta

DB_PATH = os.environ.get("DB_PATH", "./dev.db")

EVENT_IDS = {
    "Logon": 4624, "Logoff": 4634,
    "Lock": 4800, "Unlock": 4801,
    "Sleep": 42, "Resume": 107,
    "Heartbeat": 9000,
}
SOURCE = {
    "Logon": "Security", "Logoff": "Security",
    "Lock": "Security", "Unlock": "Security",
    "Sleep": "Kernel-Power", "Resume": "Kernel-Power",
    "Heartbeat": "Snapshot",
}


def at(hour, minute):
    """Local-tz ISO timestamp for today at HH:MM."""
    today = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
    return (today + timedelta(hours=hour, minutes=minute)).isoformat()


NOW = datetime.now().astimezone()
NOW_ISO = NOW.isoformat()


def mk(user, display, kind, ts, computer, **hb):
    """Build a row ready for INSERT. hb kwargs populate the heartbeat extra blob."""
    extra = {}
    if kind == "Heartbeat":
        extra["sessionState"] = "Active"
        extra["displayName"] = display
        for k in ("sessionLocked", "sessionLogonTime"):
            if k in hb:
                extra[k] = hb[k]
    return {
        "ts": ts, "computer": computer, "source": SOURCE[kind],
        "event_id": EVENT_IDS[kind], "event_type": kind, "user": user,
        "logon_type": 2 if kind == "Logon" else None,
        "idle_seconds": hb.get("idleSeconds"),
        "extra": json.dumps(extra) if extra else None,
    }


def build_events():
    events = []

    # Jane Doe — active, back from lunch.
    events += [
        mk("jane.doe", "Jane Doe", "Logon",     at(8, 42),  "DEV-JANE"),
        mk("jane.doe", "Jane Doe", "Lock",      at(12, 18), "DEV-JANE"),
        mk("jane.doe", "Jane Doe", "Unlock",    at(13, 6),  "DEV-JANE"),
        mk("jane.doe", "Jane Doe", "Heartbeat", NOW_ISO,    "DEV-JANE",
           idleSeconds=8, sessionLocked=False, sessionLogonTime=at(8, 42)),
    ]

    # Mark Smith — stepped away 15m ago, still locked.
    lock_ts = (NOW - timedelta(minutes=15)).isoformat()
    events += [
        mk("mark.smith", "Mark Smith", "Logon",     at(9, 4), "DEV-MARK"),
        mk("mark.smith", "Mark Smith", "Lock",      lock_ts,  "DEV-MARK"),
        mk("mark.smith", "Mark Smith", "Heartbeat", NOW_ISO,  "DEV-MARK",
           idleSeconds=900, sessionLocked=True, sessionLogonTime=at(9, 4)),
    ]

    # Sara Patel — early start, active.
    events += [
        mk("sara.patel", "Sara Patel", "Logon",     at(8, 12),  "DEV-SARA"),
        mk("sara.patel", "Sara Patel", "Lock",      at(12, 54), "DEV-SARA"),
        mk("sara.patel", "Sara Patel", "Unlock",    at(13, 38), "DEV-SARA"),
        mk("sara.patel", "Sara Patel", "Heartbeat", NOW_ISO,    "DEV-SARA",
           idleSeconds=30, sessionLocked=False, sessionLogonTime=at(8, 12)),
    ]

    # Tom Liu — idle (away from desk, not locked).
    events += [
        mk("tom.liu", "Tom Liu", "Logon",     at(9, 18), "DEV-TOM"),
        mk("tom.liu", "Tom Liu", "Heartbeat", NOW_ISO,   "DEV-TOM",
           idleSeconds=780, sessionLocked=False, sessionLogonTime=at(9, 18)),
    ]

    # Alex Taylor — logged off early afternoon.
    events += [
        mk("alex.taylor", "Alex Taylor", "Logon",  at(8, 30),  "DEV-ALEX"),
        mk("alex.taylor", "Alex Taylor", "Lock",   at(12, 0),  "DEV-ALEX"),
        mk("alex.taylor", "Alex Taylor", "Unlock", at(13, 0),  "DEV-ALEX"),
        mk("alex.taylor", "Alex Taylor", "Logoff", at(15, 30), "DEV-ALEX"),
    ]

    # Raj Kumar — late start, active.
    events += [
        mk("raj.kumar", "Raj Kumar", "Logon",     at(9, 45), "DEV-RAJ"),
        mk("raj.kumar", "Raj Kumar", "Heartbeat", NOW_ISO,   "DEV-RAJ",
           idleSeconds=5, sessionLocked=False, sessionLogonTime=at(9, 45)),
    ]

    # Emma Wilson — active.
    events += [
        mk("emma.wilson", "Emma Wilson", "Logon",     at(8, 55),  "DEV-EMMA"),
        mk("emma.wilson", "Emma Wilson", "Lock",      at(12, 30), "DEV-EMMA"),
        mk("emma.wilson", "Emma Wilson", "Unlock",    at(13, 15), "DEV-EMMA"),
        mk("emma.wilson", "Emma Wilson", "Heartbeat", NOW_ISO,    "DEV-EMMA",
           idleSeconds=0, sessionLocked=False, sessionLogonTime=at(8, 55)),
    ]

    # A few days of history for emma + jane so the week sparkline isn't empty.
    for days_ago in (1, 2, 3, 4):
        day = (datetime.now().astimezone() - timedelta(days=days_ago)).replace(
            hour=0, minute=0, second=0, microsecond=0)
        if day.weekday() >= 5:  # skip weekends
            continue
        def atp(hh, mm, d=day):
            return (d + timedelta(hours=hh, minutes=mm)).isoformat()
        events += [
            mk("jane.doe", "Jane Doe", "Logon",  atp(8, 45),  "DEV-JANE"),
            mk("jane.doe", "Jane Doe", "Lock",   atp(12, 30), "DEV-JANE"),
            mk("jane.doe", "Jane Doe", "Unlock", atp(13, 15), "DEV-JANE"),
            mk("jane.doe", "Jane Doe", "Logoff", atp(17, 10), "DEV-JANE"),
            mk("emma.wilson", "Emma Wilson", "Logon",  atp(8, 55),  "DEV-EMMA"),
            mk("emma.wilson", "Emma Wilson", "Lock",   atp(12, 30), "DEV-EMMA"),
            mk("emma.wilson", "Emma Wilson", "Unlock", atp(13, 15), "DEV-EMMA"),
            mk("emma.wilson", "Emma Wilson", "Logoff", atp(17, 5),  "DEV-EMMA"),
        ]

    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true",
                        help="Do not wipe existing events before seeding")
    args = parser.parse_args()

    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(db_dir, exist_ok=True)

    with closing(sqlite3.connect(DB_PATH)) as conn:
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
            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            """
        )
        if not args.keep:
            conn.execute("DELETE FROM events")

        inserted = dupes = 0
        for e in build_events():
            try:
                conn.execute(
                    """INSERT INTO events(ts, computer, source, event_id, event_type,
                                          user, logon_type, idle_seconds, extra)
                       VALUES(:ts,:computer,:source,:event_id,:event_type,
                              :user,:logon_type,:idle_seconds,:extra)""",
                    e,
                )
                inserted += 1
            except sqlite3.IntegrityError:
                dupes += 1
        conn.commit()

    print(f"Seeded {inserted} events into {DB_PATH} (dupes skipped: {dupes})")


if __name__ == "__main__":
    main()
