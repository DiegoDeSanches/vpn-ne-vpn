[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$errors = [System.Collections.Generic.List[string]]::new()

function Read-RepoFile([string]$RelativePath) {
    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        $errors.Add("Missing required file: $RelativePath")
        return ''
    }
    return Get-Content -Raw -LiteralPath $path
}

$requiredFiles = @(
    'docs/architecture.md',
    'docs/trust-boundaries.md',
    'docs/integration-plan.md',
    'docs/error-model.md',
    'docs/protocol-versioning.md',
    'proto/common/v1/common.proto',
    'proto/directory/v1/directory.proto',
    'proto/gateway/v1/gateway.proto',
    'proto/control/v1/control.proto',
    'proto/health/v1/health.proto',
    'crates/common-types/src/contracts/v1.rs'
)
$requiredFiles | ForEach-Object { [void](Read-RepoFile $_) }

$contracts = Read-RepoFile 'crates/common-types/src/contracts/v1.rs'
$requiredTraits = @(
    'TorBackend', 'CircuitManager', 'GatewayConnector', 'PacketEngine',
    'DnsEngine', 'PolicyEngine', 'KillSwitch', 'SecureStorage',
    'GatewayDirectoryProvider', 'TokenProvider', 'HealthReporter'
)
foreach ($trait in $requiredTraits) {
    if ($contracts -notmatch "pub trait $trait\b") {
        $errors.Add("Missing required Rust trait: $trait")
    }
}
foreach ($trait in $requiredTraits) {
    if ($contracts -notmatch "pub trait ${trait}:[^{\r\n]*VersionedContract") {
        $errors.Add("Trait does not extend VersionedContract: $trait")
    }
}
$transportContracts = Read-RepoFile 'crates/common-types/src/transport.rs'
foreach ($trait in @('ByteTransport', 'PacketTunnel')) {
    if ($transportContracts -notmatch "pub trait ${trait}:[^{\r\n]*VersionedContract") {
        $errors.Add("Public transport trait does not extend VersionedContract: $trait")
    }
}

$state = Read-RepoFile 'crates/common-types/src/state.rs'
$requiredStates = @(
    'Disconnected', 'Preparing', 'ApplyingKillSwitch', 'BootstrappingTor',
    'LoadingDirectory', 'SelectingGateway', 'Authenticating', 'Connected',
    'Rotating', 'Reconnecting', 'Degraded', 'Disconnecting', 'Blocked',
    'FatalError'
)
foreach ($name in $requiredStates) {
    if ($state -notmatch "\b$name\b") {
        $errors.Add("Missing client state: $name")
    }
}

$architecture = Read-RepoFile 'docs/architecture.md'
$requiredDiagramLabels = @(
    'Standard mode', 'Enhanced mode', 'Maximum mode', 'Control plane',
    'Data plane', 'participant C as client-core', 'prepare_rotation(old'
)
foreach ($label in $requiredDiagramLabels) {
    if ($architecture -notmatch [regex]::Escape($label)) {
        $errors.Add("Missing required architecture section: $label")
    }
}
$mermaidCount = ([regex]::Matches($architecture, '```mermaid')).Count
if ($mermaidCount -lt 7) {
    $errors.Add("Expected at least 7 Mermaid diagrams, found $mermaidCount")
}

$failureCount = (Get-Content -LiteralPath (Join-Path $root 'docs/error-model.md') |
    Where-Object { $_ -match '^\| F\d{2} \|' }).Count
if ($failureCount -lt 15) {
    $errors.Add("Expected at least 15 failure scenarios, found $failureCount")
}

$gateway = Read-RepoFile 'proto/gateway/v1/gateway.proto'
$gatewayWithoutComments = $gateway -replace '(?m)//.*$', ''
$identityFieldPattern = '(?i)(\b(account|user|device|payment|email)(_?[a-z0-9]*)?|\b(client|source|real)_?ip)\s*='
if ($gatewayWithoutComments -match $identityFieldPattern) {
    $errors.Add('Identity-like field found in gateway data-plane protobuf')
}
if ($gateway -match 'import\s+".*control/') {
    $errors.Add('Gateway data plane imports a control-plane protobuf')
}

$protoFiles = Get-ChildItem -Path (Join-Path $root 'proto') -Recurse -Filter '*.proto'
foreach ($file in $protoFiles) {
    $proto = Get-Content -Raw -LiteralPath $file.FullName
    if ($proto -notmatch '(?m)^package\s+onionroute\.[a-z]+\.v\d+;') {
        $errors.Add("Unversioned protobuf package: $($file.FullName)")
    }
    $openBraces = ([regex]::Matches($proto, '\{')).Count
    $closeBraces = ([regex]::Matches($proto, '\}')).Count
    if ($openBraces -ne $closeBraces) {
        $errors.Add("Unbalanced protobuf braces: $($file.FullName)")
    }
}

$mocks = Read-RepoFile 'crates/common-types/src/mocks.rs'
foreach ($trait in $requiredTraits) {
    if ($mocks -notmatch "pub struct Mock$trait\b") {
        $errors.Add("Missing mock for required trait: Mock$trait")
    }
}

$adrCount = (Get-ChildItem -Path (Join-Path $root 'docs/adr') -Filter '*.md' |
    Where-Object { $_.Name -match '^\d{4}-.+\.md$' }).Count
if ($adrCount -lt 5) {
    $errors.Add("Expected key ADRs, found only $adrCount")
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Architecture checks failed: $($errors.Count) error(s)"
}

Write-Output "Architecture checks passed: $($requiredTraits.Count) traits, $($requiredStates.Count) states, $mermaidCount Mermaid diagrams, $failureCount failure scenarios, $adrCount ADRs."
