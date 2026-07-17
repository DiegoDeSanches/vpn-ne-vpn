[CmdletBinding()]
param(
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$prototypeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $prototypeDir 'compose.yaml'
$proofFile = Join-Path $prototypeDir 'route-proof.json'

try {
    docker compose -f $composeFile down --volumes --remove-orphans | Out-Null
    docker compose -f $composeFile build
    docker compose -f $composeFile up -d gateway controlled-origin onion-service client-tor
    $proof = docker compose -f $composeFile run --rm probe
    if ($LASTEXITCODE -ne 0) {
        throw "Local route probe failed with exit code $LASTEXITCODE"
    }
    $proofLine = $proof | Where-Object { $_ -match '^\{' } | Select-Object -Last 1
    if (-not $proofLine) {
        throw 'Probe did not return route-proof JSON'
    }
    $decoded = $proofLine | ConvertFrom-Json
    if (-not $decoded.ok -or $decoded.schema -ne 'onionroute.local-prototype.route-proof.v1') {
        throw 'Probe returned an invalid route proof'
    }
    Set-Content -LiteralPath $proofFile -Value $proofLine -Encoding utf8NoBOM
    Write-Output $proofLine
}
finally {
    if (-not $KeepRunning) {
        docker compose -f $composeFile down --volumes --remove-orphans | Out-Null
    }
}

