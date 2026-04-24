[CmdletBinding()]
param(
    # Accepts either a single .jsonl file or a directory containing one .jsonl per machine
    [string]$EventsPath  = 'C:\ProgramData\ActivityMonitor\events.jsonl',
    [string]$OutputDir   = 'C:\ProgramData\ActivityMonitor\report',
    [datetime]$From      = (Get-Date).AddDays(-14).Date,
    [datetime]$To        = (Get-Date).Date.AddDays(1).AddSeconds(-1)
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $EventsPath)) { throw "Events path not found: $EventsPath" }
if (-not (Test-Path $OutputDir))  { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# --- Load from one file or a directory of files ------------------------
$inputFiles = if ((Get-Item $EventsPath).PSIsContainer) {
    Get-ChildItem $EventsPath -Filter '*.jsonl' -File | ForEach-Object { $_.FullName }
} else { @($EventsPath) }
Write-Host "Reading $($inputFiles.Count) event file(s):"
$inputFiles | ForEach-Object { Write-Host "  $_" }

$raw = foreach ($f in $inputFiles) { Get-Content $f -Encoding UTF8 | Where-Object { $_ -match '\S' } }
$events = foreach ($line in $raw) {
    try { $line | ConvertFrom-Json } catch { }
}
$events = $events | ForEach-Object {
    $t = $_.timestamp
    $dt = if ($t -is [datetime]) { $t } else { [System.Xml.XmlConvert]::ToDateTime([string]$t, [System.Xml.XmlDateTimeSerializationMode]::Local) }
    # Normalize user: strip DOMAIN\ prefix so TerminalServices and Security events merge
    $u = $_.user
    if ($u -and $u -match '\\') { $u = ($u -split '\\',2)[1] }
    $_ | Add-Member -NotePropertyName ts -NotePropertyValue $dt -Force
    $_.user = $u
    $_
} | Where-Object { $_.ts -ge $From -and $_.ts -le $To }

# Drop logon-type 7 (unlock credential auth) on 4624/4634 - redundant with 4801/4800.
$events = $events | Where-Object {
    -not (($_.eventId -in 4624,4634) -and ($_.logonType -eq 7))
}

$events = $events | Sort-Object ts

# --- Per-machine user inference ----------------------------------------
# Walk each machine's timeline. Maintain currentUser from Logon/Unlock/Heartbeat
# (clear only on matching Logoff). Fill in missing user on user-less events
# (e.g. Kernel-Power Resume/Sleep) with whoever was logged on at that instant.
foreach ($mg in ($events | Group-Object computer)) {
    $currentUser = $null
    foreach ($e in $mg.Group) {
        if ($e.eventType -in 'Logon','Unlock','Heartbeat' -and $e.user) {
            $currentUser = $e.user
        }
        elseif ($e.eventType -eq 'Logoff' -and $e.user -and $currentUser -and ($e.user -ieq $currentUser)) {
            $currentUser = $null
        }
        if (-not $e.user -and $currentUser) { $e.user = $currentUser }
    }
}

Write-Host "Loaded $($events.Count) events between $($From.ToString('yyyy-MM-dd')) and $($To.ToString('yyyy-MM-dd'))"

# --- Per-user per-day rollup -------------------------------------------
$presenceTypes = @('Logon','Logoff','Lock','Unlock','Sleep','Resume','Heartbeat')
$arrivalTypes  = @('Logon','Unlock','Resume','Heartbeat')
$departTypes   = @('Logoff','Lock','Sleep')
$presence = $events | Where-Object { $_.eventType -in $presenceTypes -and $_.user }

$summary = foreach ($group in ($presence | Group-Object { "$($_.user)|$($_.ts.Date.ToString('yyyy-MM-dd'))" })) {
    $parts = $group.Name.Split('|')
    $user  = $parts[0]; $date = [datetime]::Parse($parts[1])
    $dayEvents = $group.Group | Sort-Object ts

    $arrivals   = $dayEvents | Where-Object { $_.eventType -in $arrivalTypes }
    $departures = $dayEvents | Where-Object { $_.eventType -in $departTypes }

    $firstArrival = if ($arrivals)  { ($arrivals  | Select-Object -First 1).ts } else { $null }
    $lastActivity = if ($dayEvents) { ($dayEvents | Select-Object -Last 1).ts  } else { $null }

    # Walk the day pairing lock->unlock / sleep->resume to sum locked minutes
    $lockedMin = 0.0
    $lockStart = $null
    foreach ($e in $dayEvents) {
        if ($e.eventType -in 'Lock','Sleep') { if (-not $lockStart) { $lockStart = $e.ts } }
        elseif ($e.eventType -in 'Unlock','Resume','Logon') {
            if ($lockStart) { $lockedMin += ($e.ts - $lockStart).TotalMinutes; $lockStart = $null }
        }
    }

    $spanMin = if ($firstArrival -and $lastActivity) { ($lastActivity - $firstArrival).TotalMinutes } else { 0.0 }
    $activeMin = [math]::Max(0, $spanMin - $lockedMin)

    $machines = ($dayEvents.computer | Where-Object { $_ } | Sort-Object -Unique) -join ', '

    [pscustomobject]@{
        user          = $user
        date          = $date.ToString('yyyy-MM-dd')
        weekday       = $date.DayOfWeek
        firstArrival  = if ($firstArrival) { $firstArrival.ToString('HH:mm:ss') } else { '-' }
        lastActivity  = if ($lastActivity) { $lastActivity.ToString('HH:mm:ss') } else { '-' }
        spanMinutes   = [int]$spanMin
        lockedMinutes = [int]$lockedMin
        activeMinutes = [int]$activeMin
        machines      = $machines
        eventCount    = $dayEvents.Count
    }
}
$summary = $summary | Sort-Object user, date

# --- CSV exports -------------------------------------------------------
$csvSummary = Join-Path $OutputDir 'summary.csv'
$csvEvents  = Join-Path $OutputDir 'events.csv'
$summary | Export-Csv -Path $csvSummary -NoTypeInformation -Encoding UTF8
$events  | Select-Object timestamp,source,eventId,eventType,user,logonType,logonTypeName |
    Export-Csv -Path $csvEvents -NoTypeInformation -Encoding UTF8

# --- HTML --------------------------------------------------------------
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append(@"
<!doctype html><html><head><meta charset="utf-8"><title>Activity Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
 h1{margin:0 0 4px 0}h2{margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}
 .meta{color:#666;font-size:13px;margin-bottom:16px}
 table{border-collapse:collapse;width:100%;margin-bottom:18px;font-size:13px}
 th,td{padding:6px 10px;border-bottom:1px solid #eee;text-align:left}
 th{background:#f4f4f4}
 td.num{text-align:right;font-variant-numeric:tabular-nums}
 .weekend{background:#fafafa;color:#999}
 .bar{background:#e7f0ff;height:6px;border-radius:3px;position:relative}
 .bar>span{display:block;height:6px;border-radius:3px;background:#3b82f6}
</style></head><body>
"@)
[void]$sb.AppendFormat("<h1>Activity Report</h1><div class='meta'>{0} &rarr; {1} &middot; generated {2}</div>",
    $From.ToString('yyyy-MM-dd'), $To.ToString('yyyy-MM-dd'), (Get-Date).ToString('yyyy-MM-dd HH:mm'))

$maxActive = ($summary | Measure-Object activeMinutes -Maximum).Maximum
if (-not $maxActive -or $maxActive -eq 0) { $maxActive = 1 }

foreach ($u in ($summary | Group-Object user)) {
    [void]$sb.AppendFormat("<h2>{0}</h2>", [System.Web.HttpUtility]::HtmlEncode($u.Name))
    $totalActive = ($u.Group | Measure-Object activeMinutes -Sum).Sum
    [void]$sb.AppendFormat("<div class='meta'>Total active across range: <b>{0:F1}h</b> ({1}m)</div>", ($totalActive/60), $totalActive)
    [void]$sb.Append("<table><thead><tr><th>Date</th><th>Day</th><th>First activity</th><th>Last activity</th><th>Span</th><th>Locked</th><th>Active</th><th></th><th>Machines</th><th>Events</th></tr></thead><tbody>")
    foreach ($d in $u.Group) {
        $weekendCls = if ($d.weekday -in 'Saturday','Sunday') { ' class="weekend"' } else { '' }
        $pct = [int](100 * $d.activeMinutes / $maxActive)
        [void]$sb.AppendFormat(
            "<tr$weekendCls><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class='num'>{4}m</td><td class='num'>{5}m</td><td class='num'>{6}m</td><td style='width:140px'><div class='bar'><span style='width:{7}%'></span></div></td><td>{8}</td><td class='num'>{9}</td></tr>",
            $d.date, $d.weekday, $d.firstArrival, $d.lastActivity, $d.spanMinutes, $d.lockedMinutes, $d.activeMinutes, $pct,
            [System.Web.HttpUtility]::HtmlEncode([string]$d.machines), $d.eventCount
        )
    }
    [void]$sb.Append("</tbody></table>")
}
[void]$sb.Append("</body></html>")

Add-Type -AssemblyName System.Web
$htmlPath = Join-Path $OutputDir 'activity.html'
Set-Content -Path $htmlPath -Value $sb.ToString() -Encoding UTF8

Write-Host "Wrote:"
Write-Host "  HTML:    $htmlPath"
Write-Host "  Summary: $csvSummary"
Write-Host "  Events:  $csvEvents"
Write-Host ""
$summary | Format-Table -AutoSize
