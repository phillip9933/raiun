param(
    [string] $VersionOverride
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# BEGIN NSIS shell pin helper
function Get-NsisShellExecutablePath {
    param([Parameter(Mandatory = $true)][string] $BundleDirectory)

    $bundle = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($BundleDirectory))
    if ($bundle.Name -ine 'nsis' -or $null -eq $bundle.Parent -or $bundle.Parent.Name -ine 'bundle') {
        throw 'The selected NSIS bundle directory does not have the expected bundle/nsis layout.'
    }
    $release = $bundle.Parent.Parent
    if ($null -eq $release -or $release.Name -ine 'release') {
        throw 'The selected NSIS bundle is not nested under its release directory.'
    }
    return Join-Path $release.FullName 'raiun-desktop-shell.exe'
}

function Get-NsisShellMetadata {
    param([Parameter(Mandatory = $true)][byte[]] $ShellBytes)

    $rawMarker = '__TAURI_BUNDLE_TYPE_VAR_UNK'
    $nsisMarker = '__TAURI_BUNDLE_TYPE_VAR_NSS'
    $shellText = [System.Text.Encoding]::ASCII.GetString($ShellBytes)
    $firstMarker = $shellText.IndexOf($rawMarker, [System.StringComparison]::Ordinal)
    if ($firstMarker -lt 0 -or $shellText.IndexOf($rawMarker, $firstMarker + $rawMarker.Length, [System.StringComparison]::Ordinal) -ge 0) {
        throw 'Expected exactly one unknown Tauri bundle-type marker in the raw shell executable.'
    }
    if ($shellText.IndexOf($nsisMarker, [System.StringComparison]::Ordinal) -ge 0) {
        throw 'The raw shell executable already contains the NSIS bundle-type marker.'
    }

    $bundledBytes = [byte[]] $ShellBytes.Clone()
    $replaceOffset = $firstMarker + $rawMarker.Length - 3
    $bundledBytes[$replaceOffset] = [byte] 0x4e # N
    $bundledBytes[$replaceOffset + 1] = [byte] 0x53 # S
    $bundledBytes[$replaceOffset + 2] = [byte] 0x53 # S

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $rawHash = [System.BitConverter]::ToString($sha256.ComputeHash($ShellBytes)).Replace('-', '').ToLowerInvariant()
        $bundledHash = [System.BitConverter]::ToString($sha256.ComputeHash($bundledBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }

    return [pscustomobject] @{
        rawLength = $ShellBytes.Length
        rawSha256 = $rawHash
        rawMarker = $rawMarker
        bundledExpectedLength = $bundledBytes.Length
        bundledExpectedSha256 = $bundledHash
        bundledMarker = $nsisMarker
        transformation = 'replace the unique raw marker suffix UNK with NSIS marker suffix NSS'
    }
}
# END NSIS shell pin helper

$repoRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'prepare-windows-payload.ps1')

$versionOverlayPath = $null
if (-not [string]::IsNullOrWhiteSpace($VersionOverride)) {
    if ($VersionOverride -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
        throw 'VersionOverride must be a valid numeric semantic version.'
    }
    $overlayDir = Join-Path $repoRoot 'target'
    New-Item -ItemType Directory -Path $overlayDir -Force | Out-Null
    $versionOverlayPath = Join-Path $overlayDir 'windows-package-version-override.json'
    @{ version = $VersionOverride } | ConvertTo-Json -Compress | Set-Content -LiteralPath $versionOverlayPath -Encoding utf8
}

Push-Location (Join-Path $repoRoot 'desktop-shell')
try {
    $npm = Get-Command npm.cmd -ErrorAction Stop
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $npm.Source ci 2>&1
        $npmExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($npmExitCode -ne 0) {
        throw "Installing locked frontend dependencies failed (exit code $npmExitCode)."
    }
    $targetDir = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        Join-Path $repoRoot 'desktop-shell\src-tauri\target'
    } else {
        [System.IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
    }
    $bundleCandidates = @(
        (Join-Path $targetDir 'release\bundle\nsis'),
        (Join-Path $targetDir 'x86_64-pc-windows-msvc\release\bundle\nsis')
    )
    $bundleDir = $bundleCandidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Container
    } | Select-Object -First 1
    if (-not $bundleDir) {
        $bundleDir = $bundleCandidates[0]
    }
    $previousInstallers = @{}
    if (Test-Path -LiteralPath $bundleDir -PathType Container) {
        foreach ($previous in Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' -File) {
            $previousInstallers[$previous.Name] = (Get-FileHash -LiteralPath $previous.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $tauriArgs = @('run', 'tauri', '--', 'build', '--bundles', 'nsis', '--no-sign', '--config', 'src-tauri/tauri.windows.conf.json')
    if ($versionOverlayPath) {
        $tauriArgs += @('--config', $versionOverlayPath)
    }
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $npm.Source @tauriArgs 2>&1
        $tauriExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($tauriExitCode -ne 0) {
        throw "Building the unsigned per-user NSIS installer failed (exit code $tauriExitCode)."
    }

    $shellExecutablePath = Get-NsisShellExecutablePath -BundleDirectory $bundleDir
    if (-not (Test-Path -LiteralPath $shellExecutablePath -PathType Leaf)) {
        throw "Could not find the raw Tauri shell executable under the active Cargo target directory: $targetDir"
    }
    $shellExecutableMetadata = Get-NsisShellMetadata -ShellBytes ([System.IO.File]::ReadAllBytes($shellExecutablePath))

    if (-not (Test-Path -LiteralPath $bundleDir -PathType Container)) {
        throw "Could not find the NSIS bundle under the active Cargo target directory: $targetDir"
    }
    $changedInstallers = @(
        Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' -File | Where-Object {
            $currentHash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            -not $previousInstallers.ContainsKey($_.Name) -or $previousInstallers[$_.Name] -ne $currentHash
        }
    )
    if ($changedInstallers.Count -eq 1) {
        $installer = $changedInstallers[0]
    } elseif ($changedInstallers.Count -eq 0 -and -not $VersionOverride) {
        $existingInstallers = @(Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' -File)
        if ($existingInstallers.Count -ne 1) {
            throw "Expected one unchanged installer in $bundleDir; found $($existingInstallers.Count)."
        }
        $installer = $existingInstallers[0]
    } else {
        throw "Expected exactly one new or changed NSIS setup executable in $bundleDir; found $($changedInstallers.Count)."
    }
    $hash = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    # Filtered source archives do not carry .git metadata, and build hosts may
    # not have Git installed. Treat provenance as unavailable in either case
    # instead of letting PowerShell's Stop preference abort after packaging.
    $commit = 'unknown'
    $dirty = $true
    $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue
    if ($gitCommand) {
        $commitOutput = & $gitCommand.Source -C $repoRoot rev-parse HEAD 2>$null
        $commitExitCode = $LASTEXITCODE
        $candidateCommit = $commitOutput | Select-Object -First 1
        if ($commitExitCode -eq 0 -and $candidateCommit -match '^[0-9a-f]{40,64}$') {
            $commit = $candidateCommit
        }
        $status = & $gitCommand.Source -C $repoRoot status --porcelain --untracked-files=normal 2>$null
        if ($LASTEXITCODE -eq 0) {
            $dirty = -not [string]::IsNullOrWhiteSpace(($status -join "`n"))
        }
    }
    $payloadManifestPath = Join-Path $repoRoot 'target\windows-package-resources\payload-manifest.json'
    $payloadManifest = Get-Content -LiteralPath $payloadManifestPath -Raw | ConvertFrom-Json
    $packageManifest = [ordered]@{
        format = 'raiun-windows-installer-v1'
        target = 'x86_64-pc-windows-msvc'
        sourceCommit = $commit
        sourceDirty = $dirty
        versionOverride = if ($VersionOverride) { $VersionOverride } else { $null }
        signed = $false
        installer = [ordered]@{
            name = $installer.Name
            length = $installer.Length
            sha256 = $hash
        }
        applicationShell = [ordered]@{
            rawRelease = [ordered]@{
                name = [System.IO.Path]::GetFileName($shellExecutablePath)
                length = $shellExecutableMetadata.rawLength
                sha256 = $shellExecutableMetadata.rawSha256
                marker = $shellExecutableMetadata.rawMarker
            }
            bundledExpected = [ordered]@{
                bundleType = 'nsis'
                target = 'x64'
                length = $shellExecutableMetadata.bundledExpectedLength
                sha256 = $shellExecutableMetadata.bundledExpectedSha256
                marker = $shellExecutableMetadata.bundledMarker
                transformation = $shellExecutableMetadata.transformation
            }
        }
        payloads = $payloadManifest.payloads
    }
    $manifestPath = "$($installer.FullName).manifest.json"
    $packageManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Output "Unsigned per-user installer: $($installer.FullName)"
    Write-Output "SHA-256: $hash"
    Write-Output "Manifest: $manifestPath"
    Write-Output 'The installer has not been run or signed.'
} finally {
    if ($versionOverlayPath -and (Test-Path -LiteralPath $versionOverlayPath)) {
        Remove-Item -LiteralPath $versionOverlayPath -Force
    }
    Pop-Location
}
