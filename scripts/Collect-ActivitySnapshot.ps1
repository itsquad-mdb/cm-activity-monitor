[CmdletBinding()]
param(
    # Used only on first run (no state file yet). Bookmarks take over afterwards.
    [int]$LookbackHours = 168,
    [string]$OutputPath = 'C:\ProgramData\ActivityMonitor\events.jsonl',
    [bool]$EnableAuditPolicy = $true,
    # Optional server push. If set, new events are POSTed after local write.
    # Reads from params OR from env vars ACTIVITY_SERVER_URL / ACTIVITY_API_KEY.
    [string]$ServerUrl = $env:ACTIVITY_SERVER_URL,
    [string]$ApiKey    = $env:ACTIVITY_API_KEY,
    # One-off flag: wipe the bookmark state so this run re-reads the full LookbackHours.
    [switch]$ResetState
)

$ErrorActionPreference = 'Stop'
$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

$stateFile = Join-Path $outputDir 'state.json'
if ($ResetState -and (Test-Path $stateFile)) {
    Remove-Item $stateFile -Force
}
$state = $null
if (Test-Path $stateFile) {
    try { $state = Get-Content $stateFile -Raw | ConvertFrom-Json } catch {}
}

$bookmarks = @{ Security = [int64]0; System = [int64]0; TerminalServices = [int64]0 }
if ($state -and $state.bookmarks) {
    foreach ($n in $state.bookmarks.PSObject.Properties.Name) {
        if ($bookmarks.ContainsKey($n)) { $bookmarks[$n] = [int64]$state.bookmarks.$n }
    }
}

# Display-name cache survives across runs so we only query SAM/ADSI once per user.
$displayNameCache = @{}
if ($state -and $state.displayNames) {
    foreach ($n in $state.displayNames.PSObject.Properties.Name) {
        $displayNameCache[$n] = $state.displayNames.$n
    }
}

if ($state -and $state.lastRunUtc) {
    # Re-read with 5-min overlap to cover any in-flight events; dedupe via RecordId bookmark below
    $start = ([datetime]::Parse($state.lastRunUtc)).ToLocalTime().AddMinutes(-5)
} else {
    $start = (Get-Date).AddHours(-[math]::Abs($LookbackHours))
}

$traceLog = Join-Path $outputDir 'run-trace.log'
function Write-Trace { param([string]$Msg) Add-Content -Path $traceLog -Value "$((Get-Date).ToString('o')) $Msg" }
Write-Trace "START pid=$PID elevated=$([bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) startFrom=$($start.ToString('o')) bookmarks=Sec:$($bookmarks.Security)/Sys:$($bookmarks.System)/TS:$($bookmarks.TerminalServices)"

trap {
    Write-Trace "FATAL $($_.Exception.Message)"
    Write-Trace $_.ScriptStackTrace
    exit 2
}

function Ensure-LockUnlockAuditing {
    # Subcategory GUID for "Other Logon/Logoff Events" (stable across locales)
    $subGuid = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Trace "AuditPolicy: not admin, skipping enable"; return $false }

    $current = & auditpol /get /subcategory:$subGuid /r 2>$null | ConvertFrom-Csv
    $setting = if ($current) { $current.'Inclusion Setting' } else { $null }
    Write-Trace "AuditPolicy current: $setting"

    if ($setting -match 'Success') { return $true }

    & auditpol /set /subcategory:$subGuid /success:enable /failure:disable | Out-Null
    $after = & auditpol /get /subcategory:$subGuid /r 2>$null | ConvertFrom-Csv
    Write-Trace "AuditPolicy after set: $($after.'Inclusion Setting')"
    return ($after.'Inclusion Setting' -match 'Success')
}

if ($EnableAuditPolicy) {
    $auditEnabled = Ensure-LockUnlockAuditing
    Write-Trace "auditEnabled=$auditEnabled"
}

function Get-IdleSeconds {
    if (-not ('IdleCheck' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public class IdleCheck {
  [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
  [DllImport("kernel32.dll")] public static extern uint GetTickCount();
  [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
}
'@
    }
    $lii = New-Object IdleCheck+LASTINPUTINFO
    $lii.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($lii)
    [void][IdleCheck]::GetLastInputInfo([ref]$lii)
    [math]::Round(([IdleCheck]::GetTickCount() - $lii.dwTime) / 1000, 1)
}

function Get-SessionSnapshot {
    $sessions = @()
    try {
        $raw = & quser 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            foreach ($line in ($raw | Select-Object -Skip 1)) {
                $cols = ($line.Trim() -replace '\s{2,}', '|').Split('|')
                if ($cols.Count -ge 6) {
                    $sessions += [pscustomobject]@{
                        user        = $cols[0].TrimStart('>')
                        sessionName = $cols[1]
                        sessionId   = $cols[2]
                        state       = $cols[3]
                        idleTime    = $cols[4]
                        logonTime   = $cols[5]
                    }
                }
            }
        }
    } catch { }
    , $sessions
}

# A session is "locked" when LogonUI.exe is running inside it. Works on
# domain-joined, Entra-joined, and local sessions without needing any rights
# beyond reading the process table.
function Get-SessionLockedMap {
    $map = @{}
    try {
        $logonUi = Get-CimInstance Win32_Process -Filter "Name='LogonUI.exe'" -ErrorAction Stop
        foreach ($p in $logonUi) { $map[[int]$p.SessionId] = $true }
    } catch { }
    return $map
}

# Turn quser's "4/24/2026 9:12 AM" into ISO 8601 in local tz. Returns $null
# on parse failure so the server can fall back to the Logon event timestamp.
function ConvertTo-IsoLogonTime {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    try { return ([datetime]::Parse($Raw)).ToString('o') } catch { return $null }
}

# Resolve a SAM account name to its display/full name. Cached in state.json
# between runs to keep the lookup off the hot path.
function Get-UserDisplayName {
    param([string]$SamName, [hashtable]$Cache)
    if ([string]::IsNullOrWhiteSpace($SamName)) { return $null }
    $key = $SamName.ToLower()
    if ($Cache.ContainsKey($key)) { return $Cache[$key] }

    $name = $null
    try {
        $lu = Get-LocalUser -Name $SamName -ErrorAction Stop
        if ($lu.FullName) { $name = $lu.FullName }
    } catch { }
    if (-not $name) {
        try {
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$SamName,User"
            $full = $adsi.Properties['FullName'].Value
            if ($full) { $name = "$full" }
        } catch { }
    }
    $Cache[$key] = $name  # cache null results too, so we don't retry every 5 min
    return $name
}

function Get-EventsSafe {
    param(
        [hashtable]$FilterHashtable,
        [string]$Label
    )
    try {
        Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop
    } catch [System.Diagnostics.Eventing.Reader.EventLogException] {
        Write-Warning "[$Label] $($_.Exception.Message)"
        @()
    } catch {
        if ($_.Exception.Message -match 'No events were found') { @() }
        else { Write-Warning "[$Label] $($_.Exception.Message)"; @() }
    }
}

# Unified event types - reporter only needs to know this vocabulary
$eventTypeMap = @{
    # Security log
    4624 = 'Logon'; 4634 = 'Logoff'; 4647 = 'Logoff'
    4800 = 'Lock'; 4801 = 'Unlock'
    # Kernel-Power
    42   = 'Sleep'; 107 = 'Resume'; 566 = 'Resume'
    # TerminalServices (session manager)
    21   = 'Logon'; 22 = $null; 23 = 'Logoff'; 24 = 'Lock'; 25 = 'Unlock'
}

$securityEvents = Get-EventsSafe -Label 'Security' -FilterHashtable @{
    LogName = 'Security'; Id = 4624,4634,4647,4800,4801; StartTime = $start
} | Where-Object { [int64]$_.RecordId -gt $bookmarks.Security }
$securityAccessible = ($null -ne $securityEvents) -or (-not (Test-Path variable:securityEvents))

$kernelPowerEvents = Get-EventsSafe -Label 'Kernel-Power' -FilterHashtable @{
    LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 42,107,566; StartTime = $start
} | Where-Object { [int64]$_.RecordId -gt $bookmarks.System }

$tsEvents = Get-EventsSafe -Label 'TerminalServices' -FilterHashtable @{
    LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id = 21,22,23,24,25; StartTime = $start
} | Where-Object { [int64]$_.RecordId -gt $bookmarks.TerminalServices }

$newBookmarks = @{
    Security         = $bookmarks.Security
    System           = $bookmarks.System
    TerminalServices = $bookmarks.TerminalServices
}
foreach ($e in $securityEvents)    { if ([int64]$e.RecordId -gt $newBookmarks.Security)         { $newBookmarks.Security         = [int64]$e.RecordId } }
foreach ($e in $kernelPowerEvents) { if ([int64]$e.RecordId -gt $newBookmarks.System)           { $newBookmarks.System           = [int64]$e.RecordId } }
foreach ($e in $tsEvents)          { if ([int64]$e.RecordId -gt $newBookmarks.TerminalServices) { $newBookmarks.TerminalServices = [int64]$e.RecordId } }

$logonTypeMap = @{
    2  = 'Interactive'      # console
    3  = 'Network'
    4  = 'Batch'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials'
    10 = 'RemoteInteractive' # RDP
    11 = 'CachedInteractive'
}
$interestingLogonTypes = @(2, 7, 10, 11)
$excludedUsers = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON','DWM-','UMFD-')

function Test-ExcludedUser {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    if ($Name.EndsWith('$')) { return $true }             # computer/service accounts
    foreach ($p in $excludedUsers) {
        if ($Name -ieq $p -or $Name -ilike "$p*") { return $true }
    }
    return $false
}

$allEvents = @()
$droppedByType = 0; $droppedByUser = 0
foreach ($e in $securityEvents) {
    $user = $null; $logonType = $null
    # Security event property indices are consistent across Win10/11:
    # 4624: [5]=TargetUserName [8]=LogonType
    # 4634: [1]=TargetUserName [4]=LogonType
    # 4647/4800/4801: [1]=TargetUserName (no logon type field)
    try {
        switch ($e.Id) {
            4624 { $user = $e.Properties[5].Value; $logonType = [int]$e.Properties[8].Value }
            4634 { $user = $e.Properties[1].Value; $logonType = [int]$e.Properties[4].Value }
            default { $user = $e.Properties[1].Value }
        }
    } catch {}

    # Filter out service/SYSTEM noise on 4624/4634
    if ($e.Id -in 4624,4634) {
        if ($null -ne $logonType -and $interestingLogonTypes -notcontains $logonType) { $droppedByType++; continue }
        if (Test-ExcludedUser $user) { $droppedByUser++; continue }
    }

    $allEvents += [pscustomobject]@{
        timestamp     = $e.TimeCreated.ToString('o')
        source        = 'Security'
        eventId       = $e.Id
        eventType     = $eventTypeMap[$e.Id]
        user          = $user
        logonType     = $logonType
        logonTypeName = if ($logonType) { $logonTypeMap[$logonType] } else { $null }
    }
}
Write-Trace "Security filter: dropped logonType=$droppedByType user=$droppedByUser kept=$($allEvents.Count)"
foreach ($e in $kernelPowerEvents) {
    $allEvents += [pscustomobject]@{
        timestamp = $e.TimeCreated.ToString('o')
        source    = 'Kernel-Power'
        eventId   = $e.Id
        eventType = $eventTypeMap[$e.Id]
        user      = $null
    }
}
foreach ($e in $tsEvents) {
    # Real session user lives in the event XML <UserData><EventXML><User>...
    $user = $null
    try {
        $xml = [xml]$e.ToXml()
        $node = $xml.Event.UserData.ChildNodes | Select-Object -First 1
        if ($node) { $user = $node.User }
        if (-not $user) {
            # Fallback: try SID translate
            $user = $e.UserId.Translate([System.Security.Principal.NTAccount]).Value
        }
    } catch {}
    if ($user -match '^(NT AUTHORITY\\SYSTEM|SYSTEM)$') { continue }  # drop system-internal TS events
    $mapped = $eventTypeMap[$e.Id]
    if (-not $mapped) { continue }  # skip ShellStart / unmapped
    $allEvents += [pscustomobject]@{
        timestamp = $e.TimeCreated.ToString('o')
        source    = 'TerminalServices'
        eventId   = $e.Id
        eventType = $mapped
        user      = $user
    }
}

# Heartbeat: emit an event per active user session with current idle time.
# Gives the reporter a live "user is still here" signal even when no
# Security/Kernel-Power event has fired since the last run. Also carries the
# extra context the dashboard needs: display name, lock state, and the
# session's own logon time (so check-in is reliable even when the 4624
# Security event was missed / Security log unreadable).
$idleNow   = Get-IdleSeconds
$nowIso    = (Get-Date).ToString('o')
$lockedMap = Get-SessionLockedMap
foreach ($s in (Get-SessionSnapshot)) {
    if (Test-ExcludedUser $s.user) { continue }
    if ($s.state -notmatch '^(Active|Disc)') { continue }
    $sessionIdInt = 0; [void][int]::TryParse($s.sessionId, [ref]$sessionIdInt)
    $allEvents += [pscustomobject]@{
        timestamp        = $nowIso
        source           = 'Snapshot'
        eventId          = 9000
        eventType        = 'Heartbeat'
        user             = $s.user
        idleSeconds      = $idleNow
        sessionState     = $s.state
        sessionLocked    = [bool]$lockedMap[$sessionIdInt]
        sessionLogonTime = (ConvertTo-IsoLogonTime $s.logonTime)
        displayName      = (Get-UserDisplayName -SamName $s.user -Cache $displayNameCache)
    }
}

$allEvents = @($allEvents | Sort-Object timestamp)

$snapshot = [pscustomobject]@{
    collectedAt        = (Get-Date).ToString('o')
    computer           = $env:COMPUTERNAME
    lookbackHours      = $LookbackHours
    idleSeconds        = Get-IdleSeconds
    sessions           = Get-SessionSnapshot
    securityLogAccess  = $securityAccessible
    eventCount         = $allEvents.Count
    events             = $allEvents
}

$snapshotJson = $snapshot | ConvertTo-Json -Depth 6

if ($allEvents.Count -gt 0) {
    foreach ($ev in $allEvents) {
        $ev | Add-Member -NotePropertyName computer -NotePropertyValue $env:COMPUTERNAME -Force
        $line = $ev | ConvertTo-Json -Depth 4 -Compress
        Add-Content -Path $OutputPath -Value $line -Encoding UTF8
    }
}

# Push to central server if configured. Local write is authoritative;
# a failed push is retried on next run (bookmarks ensure no loss).
if ($ServerUrl -and $allEvents.Count -gt 0) {
    try {
        $headers = @{}
        if ($ApiKey) { $headers['X-API-Key'] = $ApiKey }
        $body = @{ computer = $env:COMPUTERNAME; events = $allEvents } | ConvertTo-Json -Depth 5 -Compress
        $pushUri = ($ServerUrl.TrimEnd('/')) + '/v1/events'
        $resp = Invoke-RestMethod -Uri $pushUri -Method Post -Headers $headers -Body $body `
                                  -ContentType 'application/json' -TimeoutSec 15 -ErrorAction Stop
        Write-Trace "push OK inserted=$($resp.inserted) dupes=$($resp.duplicates) to=$pushUri"
    } catch {
        Write-Trace "push FAILED $($_.Exception.Message)"
        # Don't fail the whole run on a push error - local file is safe
    }
}

$lastSnapshotPath = Join-Path $outputDir 'last-snapshot.json'
Set-Content -Path $lastSnapshotPath -Value $snapshotJson -Encoding UTF8

$pushInfo = if ($ServerUrl) { "push=$ServerUrl" } else { "push=disabled" }
Write-Output ("events={0}  securityLogAccess={1}  {2}" -f $allEvents.Count, $securityAccessible, $pushInfo)

$newState = [pscustomobject]@{
    lastRunUtc   = (Get-Date).ToUniversalTime().ToString('o')
    bookmarks    = $newBookmarks
    displayNames = $displayNameCache
}
$newState | ConvertTo-Json -Depth 4 | Set-Content -Path $stateFile -Encoding UTF8

Write-Trace "END events=$($allEvents.Count) securityLogAccess=$securityAccessible newBookmarks=Sec:$($newBookmarks.Security)/Sys:$($newBookmarks.System)/TS:$($newBookmarks.TerminalServices)"
