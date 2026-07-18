param(
    [string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (git rev-parse --show-toplevel 2>$null)
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot) -or -not (Test-Path -LiteralPath $RepositoryRoot)) {
    throw "Run this script inside a Git repository or pass -RepositoryRoot."
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$stagedPaths = @(git -C $RepositoryRoot ls-files --cached) | Sort-Object -Unique
$modifiedPaths = @(git -C $RepositoryRoot ls-files --modified) | Sort-Object -Unique
$untrackedPaths = @(git -C $RepositoryRoot ls-files --others --exclude-standard) | Sort-Object -Unique

$modifiedLookup = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($path in $modifiedPaths) {
    [void]$modifiedLookup.Add($path)
}

$scanItems = [System.Collections.Generic.List[object]]::new()
foreach ($path in $stagedPaths) {
    $hasDifferentWorktreeCopy = $modifiedLookup.Contains($path)
    $scanItems.Add([pscustomobject]@{
        Path = $path
        Source = if ($hasDifferentWorktreeCopy) { "index" } else { "index/worktree" }
        ReadFromIndex = $hasDifferentWorktreeCopy
    })
}

foreach ($path in $modifiedPaths) {
    $absolutePath = Join-Path $RepositoryRoot $path
    if (Test-Path -LiteralPath $absolutePath -PathType Leaf) {
        $scanItems.Add([pscustomobject]@{
            Path = $path
            Source = "worktree"
            ReadFromIndex = $false
        })
    }
}

foreach ($path in $untrackedPaths) {
    $scanItems.Add([pscustomobject]@{
        Path = $path
        Source = "worktree"
        ReadFromIndex = $false
    })
}

$secretPathPattern = '(^|/)(\.env($|\.)|id_(rsa|ed25519)$|[^/]+\.(key|pem|p12|pfx|jks|keystore|secret|seed|token)$|\.vault-token$|vault-token$|vault-password[^/]*$|\.vault-pass[^/]*$|credentials\.json$|application_default_credentials\.json$|service-account[^/]*\.json$)'
$detectors = [ordered]@{
    "private-key-header" = '-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----'
    "aws-access-key" = '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
    "github-token" = '\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b'
    "gitlab-token" = '\bglpat-[A-Za-z0-9_-]{20,255}\b'
    "slack-token" = '\bxox[baprs]-[A-Za-z0-9-]{10,255}\b'
    "google-api-key" = '\bAIza[A-Za-z0-9_-]{30,}\b'
    "stripe-secret-key" = '\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b'
    "openai-api-key" = '\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b'
    "npm-token" = '\bnpm_[A-Za-z0-9]{30,}\b'
    "pypi-token" = '\bpypi-AgEIcHlwaS5vcmcC[A-Za-z0-9_-]{30,}\b'
    "sendgrid-key" = '\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b'
    "huggingface-token" = '\bhf_[A-Za-z0-9]{30,}\b'
    "google-oauth-token" = '\bya29\.[A-Za-z0-9_-]{20,}\b'
    "jwt" = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
    "credential-in-url" = '\b[a-z][a-z0-9+.-]{2,20}://[^\s/:@]+:[^\s/@]+@'
    "bearer-token" = '(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}'
}

$findings = [System.Collections.Generic.List[object]]::new()
$skippedBinaryOrLarge = 0

foreach ($scanItem in $scanItems) {
    $relativePath = $scanItem.Path
    $normalizedPath = $relativePath.Replace("\", "/")
    if ($normalizedPath -eq ".env.example" -or $normalizedPath.EndsWith(".env.example")) {
        continue
    }

    if ($normalizedPath -match $secretPathPattern) {
        $findings.Add([pscustomobject]@{
            Detector = "secret-like-path"
            Path = $normalizedPath
            Line = 1
            Source = $scanItem.Source
        })
        continue
    }

    if ($scanItem.ReadFromIndex) {
        $size = git -C $RepositoryRoot cat-file -s ":$normalizedPath" 2>$null
        if ($LASTEXITCODE -ne 0 -or [long]$size -gt 5MB) {
            $skippedBinaryOrLarge++
            continue
        }

        $content = @(git -C $RepositoryRoot show --no-textconv ":$normalizedPath" 2>$null) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            $skippedBinaryOrLarge++
            continue
        }
    } else {
        $absolutePath = Join-Path $RepositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
            continue
        }

        # PowerShell treats dotfiles as hidden on Unix. Keep them in scope: they
        # are valid commit candidates and must not bypass the secret scanner.
        $file = Get-Item -LiteralPath $absolutePath -Force
        if ($file.Length -gt 5MB) {
            $skippedBinaryOrLarge++
            continue
        }

        try {
            $content = [IO.File]::ReadAllText($absolutePath)
        } catch {
            $skippedBinaryOrLarge++
            continue
        }
    }

    if ($content.Contains([char]0)) {
        $skippedBinaryOrLarge++
        continue
    }

    foreach ($detector in $detectors.GetEnumerator()) {
        foreach ($match in [regex]::Matches($content, $detector.Value, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $line = 1 + ($content.Substring(0, $match.Index).Split("`n").Length - 1)
            $findings.Add([pscustomobject]@{
                Detector = $detector.Key
                Path = $normalizedPath
                Line = $line
                Source = $scanItem.Source
            })
        }
    }
}

$findings = @($findings | Sort-Object Detector, Path, Line -Unique)
if ($findings.Count -gt 0) {
    Write-Error "Potential secrets found. Values are intentionally not printed."
    $findings | Format-Table Detector, Path, Line, Source -AutoSize
    exit 1
}

$distinctPaths = @($scanItems.Path | Sort-Object -Unique).Count
Write-Output "Secret scan passed: $distinctPaths commit candidates and $($scanItems.Count) index/worktree snapshots checked; $skippedBinaryOrLarge binary or large files skipped."
exit 0
