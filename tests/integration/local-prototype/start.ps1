[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$OwnerNonce,

    [switch]$NoBuild,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$prototypeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $prototypeDir 'compose.yaml'
$runtimeFile = Join-Path $prototypeDir 'runtime.json'
$proofFile = Join-Path $prototypeDir 'route-proof.json'
$logFile = Join-Path $prototypeDir 'lifecycle.log'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

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

function Invoke-ComposeQuiet([string[]]$Arguments) {
    # Windows PowerShell 5 promotes native stderr to error records. Compose
    # writes normal progress there, so rely on its process exit code instead.
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

function Invoke-ComposeCapture([string[]]$Arguments) {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & docker compose -f $composeFile @Arguments 2>> $logFile
        $composeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($composeExitCode -ne 0) {
        throw "docker compose failed; see $logFile"
    }
    return $output
}

$ownerHash = Get-Sha256Hex $OwnerNonce

if (Test-Path -LiteralPath $runtimeFile) {
    try {
        $existing = Get-Content -LiteralPath $runtimeFile -Raw | ConvertFrom-Json
    }
    catch {
        if (-not $Force) {
            throw 'Existing runtime.json is invalid; use -Force for explicit recovery'
        }
        $existing = $null
    }
    if ($existing -and
        $existing.schema -ne 'onionroute.local-prototype.lifecycle-stopped.v1' -and
        $existing.owner_nonce_sha256 -and
        $existing.owner_nonce_sha256 -ne $ownerHash -and
        -not $Force) {
        throw 'Local prototype is owned by a different lifecycle nonce'
    }
}

if ($Force) {
    Invoke-ComposeQuiet @('down', '--volumes', '--remove-orphans')
}

if (-not $NoBuild) {
    Invoke-ComposeQuiet @('build')
}
Invoke-ComposeQuiet @(
    'up', '-d', '--wait', '--wait-timeout', '240',
    'gateway', 'controlled-origin', 'onion-service', 'client-tor', 'probe-server'
)

$probeOutput = Invoke-ComposeCapture @('run', '--rm', '--no-deps', 'probe')
$proofLine = $probeOutput | Where-Object { $_ -match '^\{' } | Select-Object -Last 1
if (-not $proofLine) {
    throw 'route probe returned no machine-readable proof'
}
$proof = $proofLine | ConvertFrom-Json
if (-not $proof.ok -or
    $proof.schema -ne 'onionroute.local-prototype.route-proof.v1' -or
    $proof.transport -ne 'socks5+tor-v3-onion+tls1.3+gateway-v1-adapter') {
    throw 'route probe returned an invalid proof'
}
[System.IO.File]::WriteAllText($proofFile, $proofLine, $utf8NoBom)
$proofHash = Get-Sha256Hex $proofLine

$publicRuntime = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:19091/v1/runtime' -TimeoutSec 5
if ($publicRuntime.schema -ne 'onionroute.local-prototype.runtime.v1' -or
    $publicRuntime.onion_service -notmatch '^[a-z2-7]{56}\.onion$') {
    throw 'probe API returned invalid runtime metadata'
}

$ready = [ordered]@{
    schema = 'onionroute.local-prototype.lifecycle-ready.v1'
    ok = $true
    owner_nonce_sha256 = $ownerHash
    transport = 'socks5+tor-v3-onion+tls1.3+gateway-v1-adapter'
    socks_endpoint = '127.0.0.1:19050'
    probe_endpoint = 'http://127.0.0.1:19091/v1/probe'
    probe_schema = 'onionroute.local-prototype.daemon-probe.v1'
    gateway_id = 'local-prototype-gateway'
    onion_service = $publicRuntime.onion_service
    route_proof_sha256 = $proofHash
}
$readyJson = $ready | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($runtimeFile, $readyJson, $utf8NoBom)
Write-Output $readyJson
