[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$OwnerNonce,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$prototypeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $prototypeDir 'compose.yaml'
$runtimeFile = Join-Path $prototypeDir 'runtime.json'
$logFile = Join-Path $prototypeDir 'lifecycle.log'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Invoke-ComposeQuiet([string[]]$Arguments) {
    # Compose writes normal progress to stderr. Windows PowerShell 5 turns
    # that stream into error records, so the native exit code is authoritative.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & docker compose -f $composeFile @Arguments *>> $logFile
        $composeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($composeExitCode -ne 0) {
        throw "docker compose failed; see $logFile"
    }
}

function Get-Sha256Hex([string]$Value) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Test-ListenerClosed([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(750)) {
            return $true
        }
        try {
            $client.EndConnect($pending)
            return $false
        }
        catch {
            return $true
        }
    }
    finally {
        $client.Dispose()
    }
}

$ownerHash = Get-Sha256Hex $OwnerNonce
if (-not (Test-Path -LiteralPath $runtimeFile) -and -not $Force) {
    throw 'runtime.json is missing; ownership cannot be verified'
}
if (Test-Path -LiteralPath $runtimeFile) {
    try {
        $runtime = Get-Content -LiteralPath $runtimeFile -Raw | ConvertFrom-Json
    }
    catch {
        if (-not $Force) {
            throw 'runtime.json is invalid; use -Force for explicit recovery'
        }
        $runtime = $null
    }
    if ($runtime -and $runtime.owner_nonce_sha256 -ne $ownerHash -and -not $Force) {
        throw 'Lifecycle owner nonce does not match runtime.json'
    }
}

Invoke-ComposeQuiet @('down', '--volumes', '--remove-orphans')

$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $socksClosed = Test-ListenerClosed 19050
    $probeClosed = Test-ListenerClosed 19091
    if ($socksClosed -and $probeClosed) {
        break
    }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)

if (-not $socksClosed -or -not $probeClosed) {
    throw 'Local prototype listeners remained reachable after compose down'
}

$stopped = [ordered]@{
    schema = 'onionroute.local-prototype.lifecycle-stopped.v1'
    ok = $true
    owner_nonce_sha256 = $ownerHash
    socks_listener_closed = $true
    probe_listener_closed = $true
}
$stoppedJson = $stopped | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($runtimeFile, $stoppedJson, $utf8NoBom)
Write-Output $stoppedJson
