# vlb.ps1 — one-shot Windows launcher for the Virtual Load Balancer.
#
# Usage (from the repo root):
#   .\scripts\vlb.ps1                 # build (if needed) + start daemon + status
#   .\scripts\vlb.ps1 tui             # attach the btop-style dashboard
#   .\scripts\vlb.ps1 stop            # stop the background daemon
#   .\scripts\vlb.ps1 status          # show daemon status
#   .\scripts\vlb.ps1 build|check|run|logs|stats|system
#
# NOTE: the real forwarding / iptables / ip-rule work is Linux-only. On
# Windows this launcher is primarily useful for `build`, `check`, `tui`,
# `stats`, `system` and for developing against a local non-root daemon.

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Command = 'up',
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'

$RepoDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoDir

$VlbConfig = if ($env:VLB_CONFIG) { $env:VLB_CONFIG } else { Join-Path $RepoDir 'examples/vlb.example.toml' }
$VlbBin    = if ($env:VLB_BIN)    { $env:VLB_BIN }    else { Join-Path $RepoDir 'target\release\vlb.exe' }
$VlbPid    = if ($env:VLB_PID)    { $env:VLB_PID }    else { Join-Path $env:TEMP 'vlb.pid' }
$VlbLog    = if ($env:VLB_LOG)    { $env:VLB_LOG }    else { Join-Path $env:TEMP 'vlb.log' }

function Write-Info ($msg) { Write-Host "[vlb] $msg" -ForegroundColor Cyan }
function Write-Ok   ($msg) { Write-Host "[ ok] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[!! ] $msg" -ForegroundColor Yellow }
function Die ($msg) { Write-Host "[err] $msg" -ForegroundColor Red; exit 1 }

function Ensure-Bin {
    if (-not (Test-Path $VlbBin)) {
        Write-Info "building release binary..."
        $lockArgs = @()
        if (Test-Path (Join-Path $RepoDir 'Cargo.lock')) { $lockArgs += '--locked' }
        & cargo build --release @lockArgs
        if ($LASTEXITCODE -ne 0) { Die "cargo build failed" }
    }
}

function Ensure-Cfg {
    if (-not (Test-Path $VlbConfig)) { Die "config not readable: $VlbConfig" }
}

function Get-VlbPid {
    if (-not (Test-Path $VlbPid)) { return $null }
    $pidValue = Get-Content $VlbPid -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pidValue) { return $null }
    try {
        $proc = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
        return $proc.Id
    } catch {
        return $null
    }
}

function Cmd-Build  { Ensure-Bin; Write-Ok "built: $VlbBin" }
function Cmd-Check  { Ensure-Bin; Ensure-Cfg; & $VlbBin --config $VlbConfig check }
function Cmd-Run    { Ensure-Bin; Ensure-Cfg; & $VlbBin --config $VlbConfig run }

function Cmd-Start {
    Ensure-Bin; Ensure-Cfg
    $existing = Get-VlbPid
    if ($existing) { Write-Warn2 "already running (pid $existing)"; return }
    & $VlbBin --config $VlbConfig check
    if ($LASTEXITCODE -ne 0) { Die "config check failed" }
    Write-Info "starting daemon, log=$VlbLog pid=$VlbPid"
    $proc = Start-Process -FilePath $VlbBin `
        -ArgumentList @('--config', $VlbConfig, 'run') `
        -RedirectStandardOutput $VlbLog `
        -RedirectStandardError ([string]$VlbLog + '.err') `
        -WindowStyle Hidden -PassThru
    Set-Content -Path $VlbPid -Value $proc.Id -Encoding ascii
    Start-Sleep -Milliseconds 600
    $running = Get-VlbPid
    if ($running) { Write-Ok "started pid=$running" }
    else { Die "daemon exited immediately — see $VlbLog" }
}

function Cmd-Stop {
    $pidValue = Get-VlbPid
    if (-not $pidValue) { Write-Warn2 "not running"; Remove-Item $VlbPid -ErrorAction SilentlyContinue; return }
    Write-Info "stopping pid=$pidValue"
    try { Stop-Process -Id $pidValue -ErrorAction Stop } catch { }
    for ($i = 0; $i -lt 50; $i++) {
        if (-not (Get-VlbPid)) { break }
        Start-Sleep -Milliseconds 100
    }
    if (Get-VlbPid) { Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue }
    Remove-Item $VlbPid -ErrorAction SilentlyContinue
    Write-Ok "stopped"
}

function Cmd-Restart { Cmd-Stop; Cmd-Start }

function Cmd-Status {
    Ensure-Bin; Ensure-Cfg
    $pidValue = Get-VlbPid
    if ($pidValue) { Write-Ok "daemon pid=$pidValue" } else { Write-Warn2 "daemon not running via $VlbPid" }
    try { & $VlbBin --config $VlbConfig status } catch { }
}

function Cmd-Tui    { Ensure-Bin; Ensure-Cfg; & $VlbBin --config $VlbConfig tui }
function Cmd-Stats  { Ensure-Bin; Ensure-Cfg; & $VlbBin --config $VlbConfig stats @Rest }
function Cmd-System { Ensure-Bin; Ensure-Cfg; & $VlbBin --config $VlbConfig system @Rest }

function Cmd-Logs {
    if (-not (Test-Path $VlbLog)) { Die "no log file at $VlbLog" }
    Get-Content $VlbLog -Tail 200 -Wait
}

function Cmd-Up {
    # The "just run it" path: build if needed, start daemon, print status.
    Ensure-Bin; Ensure-Cfg
    if (-not (Get-VlbPid)) { Cmd-Start } else { Write-Info "already running" }
    Cmd-Status
    Write-Info "attach dashboard:   .\scripts\vlb.ps1 tui"
    Write-Info "stop daemon:        .\scripts\vlb.ps1 stop"
}

switch ($Command) {
    'up'       { Cmd-Up }
    'build'    { Cmd-Build }
    'check'    { Cmd-Check }
    'run'      { Cmd-Run }
    'start'    { Cmd-Start }
    'stop'     { Cmd-Stop }
    'restart'  { Cmd-Restart }
    'status'   { Cmd-Status }
    'tui'      { Cmd-Tui }
    'stats'    { Cmd-Stats }
    'system'   { Cmd-System }
    'logs'     { Cmd-Logs }
    'help'     { Get-Help $PSCommandPath -Detailed }
    default    { Die "unknown command: $Command (try: .\scripts\vlb.ps1 help)" }
}
