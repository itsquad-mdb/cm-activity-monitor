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
