[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$')]
    [string] $ImageTag = 'onionroute-daemon-cross:rust-1.78-bookworm'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-DockerChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & $script:DockerPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
}

$docker = Get-Command docker.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $docker) {
    throw 'Docker CLI was not found. Install and start Docker Desktop with Linux containers.'
}
$script:DockerPath = [string] $docker.Source

& $script:DockerPath info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker engine is unavailable. Start Docker Desktop and select Linux containers.'
}

$helperDirectory = [System.IO.Path]::GetFullPath($PSScriptRoot)
$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $helperDirectory '..\..\..\..\..')
)
$daemonManifest = Join-Path $repositoryRoot 'clients\desktop\crates\daemon\Cargo.toml'
$desktopLock = Join-Path $repositoryRoot 'clients\desktop\Cargo.lock'
if (-not (Test-Path -LiteralPath $daemonManifest -PathType Leaf)) {
    throw "Daemon manifest was not found at $daemonManifest"
}
if (-not (Test-Path -LiteralPath $desktopLock -PathType Leaf)) {
    throw "Desktop Cargo.lock was not found at $desktopLock; a locked build is required."
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $resolvedOutput -PathType Leaf) {
    throw "OutputDirectory points to a file: $resolvedOutput"
}
if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $resolvedOutput -Force
}

$writeProbe = Join-Path $resolvedOutput ('.onionroute-write-test-' + [guid]::NewGuid().ToString('N'))
try {
    [System.IO.File]::WriteAllBytes($writeProbe, [byte[]] @(0x4f, 0x52))
} finally {
    if (Test-Path -LiteralPath $writeProbe) {
        Remove-Item -LiteralPath $writeProbe -Force
    }
}

$dockerfile = Join-Path $helperDirectory 'Dockerfile'
if (-not (Test-Path -LiteralPath $dockerfile -PathType Leaf)) {
    throw "Dockerfile was not found at $dockerfile"
}

Invoke-DockerChecked -Arguments @(
    'build',
    '--platform', 'linux/amd64',
    '--file', $dockerfile,
    '--tag', $ImageTag,
    $helperDirectory
)

$artifact = Join-Path $resolvedOutput 'onionroute-desktop-daemon.exe'
$stagedArtifact = Join-Path $resolvedOutput '.onionroute-desktop-daemon.exe.container'
$stagedChecksum = "$stagedArtifact.sha256"
foreach ($stalePath in @($stagedArtifact, $stagedChecksum)) {
    if (Test-Path -LiteralPath $stalePath) {
        Remove-Item -LiteralPath $stalePath -Force
    }
}
try {
    Invoke-DockerChecked -Arguments @(
        'run', '--rm',
        '--platform', 'linux/amd64',
        '--mount', "type=bind,source=$repositoryRoot,target=/workspace,readonly",
        '--mount', "type=bind,source=$resolvedOutput,target=/output",
        $ImageTag
    )

    if (-not (Test-Path -LiteralPath $stagedArtifact -PathType Leaf)) {
        throw "Container completed without producing $stagedArtifact"
    }
    $stagedInfo = Get-Item -LiteralPath $stagedArtifact
    if ($stagedInfo.Length -le 0) {
        throw "Produced daemon staging artifact is empty: $stagedArtifact"
    }
    if (-not (Test-Path -LiteralPath $stagedChecksum -PathType Leaf)) {
        throw "Container completed without producing $stagedChecksum"
    }
    $containerDigest = (Get-Content -LiteralPath $stagedChecksum -Raw).Trim().ToUpperInvariant()
    if ($containerDigest -notmatch '^[0-9A-F]{64}$') {
        throw "Container produced an invalid SHA-256 value: $stagedChecksum"
    }
    $hostStagedDigest = (Get-FileHash -LiteralPath $stagedArtifact -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($hostStagedDigest -ne $containerDigest) {
        throw 'Docker bind-mount integrity check failed for the staged daemon executable.'
    }
    Move-Item -LiteralPath $stagedArtifact -Destination $artifact -Force
} finally {
    foreach ($stalePath in @($stagedArtifact, $stagedChecksum)) {
        if (Test-Path -LiteralPath $stalePath) {
            Remove-Item -LiteralPath $stalePath -Force
        }
    }
}

$artifactInfo = Get-Item -LiteralPath $artifact
$digest = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToUpperInvariant()
$checksum = Join-Path $resolvedOutput 'onionroute-desktop-daemon.exe.sha256'
[System.IO.File]::WriteAllText(
    $checksum,
    "$digest  onionroute-desktop-daemon.exe`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Built: $artifact"
Write-Host "Size: $($artifactInfo.Length) bytes"
Write-Host "SHA-256: $digest"
