#Requires -Version 5.1
<#
.SYNOPSIS
    Run the Activity Monitor server locally with hot-reload and seeded demo data.

.EXAMPLE
    .\dev\dev.ps1                 # re-seed dev.db and start uvicorn
    .\dev\dev.ps1 -NoSeed         # start without wiping the DB
    .\dev\dev.ps1 -Port 8080      # use a different port
#>
[CmdletBinding()]
param(
    [switch]$NoSeed,
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# Local SQLite file lives next to the repo so it's easy to blow away.
$env:DB_PATH = Join-Path $repoRoot 'dev.db'
Write-Host "repo      = $repoRoot"
Write-Host "DB_PATH   = $env:DB_PATH"
Write-Host "Port      = $Port"

# First run needs the deps once.
$installed = $false
try { python -c "import fastapi, uvicorn, jinja2" 2>$null; $installed = ($LASTEXITCODE -eq 0) } catch {}
if (-not $installed) {
    Write-Host "Installing server requirements..."
    python -m pip install -r server/requirements.txt
}

if (-not $NoSeed) {
    Write-Host "Seeding dev DB..."
    python dev/seed.py
}

Write-Host ""
Write-Host "Dashboard: http://localhost:$Port" -ForegroundColor Cyan
Write-Host "API:       http://localhost:$Port/v1/status" -ForegroundColor Cyan
Write-Host "Ctrl-C to stop. Server + template changes hot-reload automatically."
Write-Host ""

# --reload watches server/*.py; Jinja auto-reloads templates every request.
python -m uvicorn server.app:app --reload --reload-dir server --port $Port
