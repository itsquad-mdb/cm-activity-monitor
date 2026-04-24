# Activity Monitor

Non-invasive Windows presence monitoring for timesheet-style reporting.

Endpoints run a PowerShell collector as SYSTEM (via NinjaOne or Scheduled Task) that captures logon/logoff/lock/unlock/sleep/resume events plus periodic idle-time heartbeats. Events are appended to a local JSONL file and optionally pushed to a central server.

## Components

```
scripts/
  Collect-ActivitySnapshot.ps1   - Endpoint collector (runs as SYSTEM)
  Build-ActivityReport.ps1       - Report generator (HTML + CSV)

server/
  app.py                         - FastAPI + SQLite ingest + query API
  Dockerfile
  docker-compose.yml             - Dokploy-ready stack with Traefik labels
  requirements.txt
```

## Endpoint → Server flow

1. Collector runs every 5 min (NinjaOne scheduled automation).
2. Reads new events from Windows event logs since last bookmark.
3. Writes JSONL locally (`C:\ProgramData\ActivityMonitor\events.jsonl`).
4. If `ACTIVITY_SERVER_URL` is set, POSTs new events to `/v1/events`.

## Server

FastAPI app, SQLite storage at `/data/activity.db`. Access controlled via Traefik IP whitelist (configure `ALLOWED_IPS` env). Endpoints:

- `POST /v1/events` - ingest a batch from one endpoint
- `GET  /v1/events?from=&to=&user=&computer=` - query events
- `GET  /v1/computers` - list reporting machines
- `GET  /v1/users` - list users seen
- `GET  /health`

## Deployment

Designed for Dokploy on Aquila. See `server/docker-compose.yml`.

## Development

Local runner for iterating on the server + dashboard without touching prod:

```powershell
.\dev\dev.ps1            # seed dev.db with a demo team and start uvicorn on :8000
.\dev\dev.ps1 -NoSeed    # skip the re-seed (keeps whatever's in dev.db)
.\dev\dev.ps1 -Port 8080
```

- Dashboard: http://localhost:8000
- DB lives at `./dev.db` (gitignored — safe to delete any time)
- `server/*.py` changes hot-reload via uvicorn; template edits hot-reload via Jinja
- `dev/seed.py` builds ~7 users with varied states (active, locked, idle, logged-off, late/early starts) plus 3–4 days of history so the week sparkline isn't empty

### Testing the collector against the local server

Run the PowerShell collector pointing at the dev server (non-elevated is fine
for testing the heartbeat push — Security-log events need SYSTEM/admin):

```powershell
.\scripts\Collect-ActivitySnapshot.ps1 `
    -ServerUrl  http://localhost:8000 `
    -OutputPath .\dev-events.jsonl
```

Each run emits heartbeats for the current session (with `displayName`,
`sessionLocked`, `sessionLogonTime`) and POSTs them to the dev server. Refresh
the dashboard to see your own machine appear in the roster.
