param(
    [string] $VersionOverride,
    [switch] $UpdaterArtifacts,
    [switch] $UpdaterRelease
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

# BEGIN updater archive selector
function Get-ChangedNsisUpdaterArchive {
    param(
        [Parameter(Mandatory = $true)][string] $BundleDirectory,
        [Parameter(Mandatory = $true)][hashtable] $PreviousHashes,
        [Parameter(Mandatory = $true)][string] $InstallerName
    )

    $changed = @(
        Get-ChildItem -LiteralPath $BundleDirectory -Filter '*.nsis.zip' -File | Where-Object {
            $currentHash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            -not $PreviousHashes.ContainsKey($_.Name) -or $PreviousHashes[$_.Name] -ne $currentHash
        }
    )
    if ($changed.Count -ne 1) {
        throw "Expected exactly one new or changed NSIS updater archive in $BundleDirectory; found $($changed.Count)."
    }
    $expectedName = [System.IO.Path]::GetFileNameWithoutExtension($InstallerName) + '.nsis.zip'
    if ($changed[0].Name -ne $expectedName) {
        throw 'The NSIS updater archive does not match the selected setup.exe.'
    }
    return $changed[0]
}
# END updater archive selector

# BEGIN default updater public key
function Initialize-UpdaterPublicKey {
    param([Parameter(Mandatory = $true)][string] $DesktopRoot)

    if ([string]::IsNullOrEmpty($env:RAIUN_DESKTOP_UPDATE_PUBKEY)) {
        $publicKeyPath = Join-Path $DesktopRoot 'desktop-shell\update-public-key.pub'
        if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) {
            throw "Updater artifact packaging requires the public key file: $publicKeyPath"
        }
        $env:RAIUN_DESKTOP_UPDATE_PUBKEY = (Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($env:RAIUN_DESKTOP_UPDATE_PUBKEY)) {
        throw 'RAIUN_DESKTOP_UPDATE_PUBKEY must contain a nonempty public key.'
    }
}
# END default updater public key

# BEGIN safe updater archive staging
function Assert-NewUpdaterArchiveCopy {
    param(
        [Parameter(Mandatory = $true)][string] $SourcePath,
        [Parameter(Mandatory = $true)][string] $DestinationPath,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256,
        [Parameter(Mandatory = $true)][long] $ExpectedLength
    )

    $source = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    $staged = Get-Item -LiteralPath $DestinationPath -ErrorAction Stop
    $sourceHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $stagedHash = (Get-FileHash -LiteralPath $staged.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($source.Length -ne $ExpectedLength -or $sourceHash -ne $ExpectedSha256 -or
        $staged.Length -ne $ExpectedLength -or $stagedHash -ne $ExpectedSha256) {
        throw 'The staged updater archive failed source and destination byte-count/hash readback.'
    }
    return $staged
}

function Copy-NewUpdaterArchive {
    param(
        [Parameter(Mandatory = $true)][string] $SourcePath,
        [Parameter(Mandatory = $true)][string] $DestinationDirectory,
        [Parameter(Mandatory = $true)][string] $DestinationName,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256,
        [Parameter(Mandatory = $true)][long] $ExpectedLength
    )

    if ($DestinationName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
        [System.IO.Path]::GetFileName($DestinationName) -ne $DestinationName) {
        throw 'The public updater archive name must be a safe ASCII basename.'
    }
    if (Test-Path -LiteralPath $DestinationDirectory) {
        throw "Refusing to reuse an existing updater release output directory: $DestinationDirectory"
    }
    $source = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if ($source.PSIsContainer -or $source.Length -ne $ExpectedLength) {
        throw 'The selected Tauri updater archive length changed before staging.'
    }
    $sourceHashBefore = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHashBefore -ne $ExpectedSha256) {
        throw 'The selected Tauri updater archive hash changed before staging.'
    }

    [void][System.IO.Directory]::CreateDirectory($DestinationDirectory)
    $destinationPath = Join-Path $DestinationDirectory $DestinationName
    $sourceStream = $null
    $destinationStream = $null
    try {
        $sourceStream = [System.IO.File]::Open($source.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $destinationStream = [System.IO.File]::Open($destinationPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $sourceStream.CopyTo($destinationStream)
        $destinationStream.Flush($true)
    } finally {
        if ($destinationStream) { $destinationStream.Dispose() }
        if ($sourceStream) { $sourceStream.Dispose() }
    }

    return Assert-NewUpdaterArchiveCopy -SourcePath $source.FullName `
        -DestinationPath $destinationPath -ExpectedSha256 $ExpectedSha256 -ExpectedLength $ExpectedLength
}
# END safe updater archive staging

$repoRoot = Split-Path -Parent $PSScriptRoot
Initialize-UpdaterPublicKey -DesktopRoot $repoRoot
$updaterArtifacts = $UpdaterArtifacts -or $UpdaterRelease
$updaterVersion = $null
if ($updaterArtifacts) {
    if ($UpdaterRelease) {
        if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PATH) -or
            -not (Test-Path -LiteralPath $env:TAURI_SIGNING_PRIVATE_KEY_PATH -PathType Leaf)) {
            throw 'Updater release signing requires TAURI_SIGNING_PRIVATE_KEY_PATH to name a key file.'
        }
        $env:TAURI_SIGNING_PRIVATE_KEY_PATH = [System.IO.Path]::GetFullPath($env:TAURI_SIGNING_PRIVATE_KEY_PATH)
    }
    $updaterVersion = $VersionOverride
    if ([string]::IsNullOrWhiteSpace($updaterVersion)) {
        $baseConfigPath = Join-Path $repoRoot 'desktop-shell\src-tauri\tauri.conf.json'
        $updaterVersion = (Get-Content -LiteralPath $baseConfigPath -Raw | ConvertFrom-Json).version
    }
    if ([string]::IsNullOrWhiteSpace($updaterVersion)) {
        throw 'Could not resolve the Tauri app version for updater packaging.'
    }
    if ($updaterVersion -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
        throw 'Updater release version must be a safe semantic version.'
    }
    $frontendVersion = (Get-Content -LiteralPath (Join-Path $repoRoot 'desktop-shell\package.json') -Raw | ConvertFrom-Json).version
    $cargoText = Get-Content -LiteralPath (Join-Path $repoRoot 'desktop-shell\src-tauri\Cargo.toml') -Raw
    $packageSection = [regex]::Match($cargoText, '(?ms)^\[package\]\s*(.*?)(?=^\[|\z)').Groups[1].Value
    $cargoVersionMatch = [regex]::Match($packageSection, '(?m)^\s*version\s*=\s*"([^"]+)"\s*$')
    if (-not $cargoVersionMatch.Success -or $updaterVersion -ne $frontendVersion -or
        $updaterVersion -ne $cargoVersionMatch.Groups[1].Value) {
        throw 'Updater release version must match package.json and the Tauri shell Cargo package version.'
    }
    if (-not $VersionOverride) {
        $baseConfigPath = Join-Path $repoRoot 'desktop-shell\src-tauri\tauri.conf.json'
        $configuredVersion = (Get-Content -LiteralPath $baseConfigPath -Raw | ConvertFrom-Json).version
        if ($updaterVersion -ne $configuredVersion) {
            throw 'Updater release version does not match tauri.conf.json.'
        }
    }
}
# BEGIN package Cargo target normalization
# Resolve a supplied relative target once, before payload and Tauri change cwd.
# The absent setting keeps each build's existing default target directory.
if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    $env:CARGO_TARGET_DIR = if ([System.IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) {
        [System.IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $env:CARGO_TARGET_DIR))
    }
}
# END package Cargo target normalization
$node = Get-Command node.exe -ErrorAction Stop
& $node.Source (Join-Path $PSScriptRoot 'check-tauri-versions.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Tauri Rust/frontend version preflight failed before payload compilation.' }
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
    if ($updaterArtifacts -and (Test-Path -LiteralPath $bundleDir -PathType Container) -and
        @(Get-ChildItem -LiteralPath $bundleDir -Filter '*.nsis.zip' -File).Count -gt 0) {
        throw "Updater release refuses to replace existing NSIS updater archives; choose a fresh CARGO_TARGET_DIR: $bundleDir"
    }
    $previousInstallers = @{}
    $previousUpdaterArchives = @{}
    if (Test-Path -LiteralPath $bundleDir -PathType Container) {
        foreach ($previous in Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' -File) {
            $previousInstallers[$previous.Name] = (Get-FileHash -LiteralPath $previous.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        foreach ($previous in Get-ChildItem -LiteralPath $bundleDir -Filter '*.nsis.zip' -File) {
            $previousUpdaterArchives[$previous.Name] = (Get-FileHash -LiteralPath $previous.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $tauriArgs = @('run', 'tauri', '--', 'build', '--bundles', 'nsis', '--no-sign', '--config', 'src-tauri/tauri.windows.conf.json')
    if ($versionOverlayPath) {
        $tauriArgs += @('--config', $versionOverlayPath)
    }
    if ($updaterArtifacts) {
        # The common release overlay enables updater artifact generation;
        # the Windows overlay selects the legacy NSIS zip used by this app.
        # --no-sign remains enabled; the exact final zip is signed below.
        $tauriArgs += @('--config', 'src-tauri/tauri.updater-release.conf.json', '--config', 'src-tauri/tauri.updater-release-windows.conf.json')
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
    $updaterArchive = $null
    $updaterSignature = $null
    if ($updaterArtifacts) {
        $originalUpdaterArchive = Get-ChangedNsisUpdaterArchive -BundleDirectory $bundleDir -PreviousHashes $previousUpdaterArchives -InstallerName $installer.Name
        $originalUpdaterArchiveLength = [long] $originalUpdaterArchive.Length
        $originalUpdaterArchiveSha256 = (Get-FileHash -LiteralPath $originalUpdaterArchive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $updaterOutputDirectory = Join-Path (Join-Path $repoRoot 'target\updater-release-assets') $updaterVersion
        $updaterArchive = Copy-NewUpdaterArchive -SourcePath $originalUpdaterArchive.FullName `
            -DestinationDirectory $updaterOutputDirectory `
            -DestinationName 'raiun-desktop-windows-x86_64.nsis.zip' `
            -ExpectedSha256 $originalUpdaterArchiveSha256 `
            -ExpectedLength $originalUpdaterArchiveLength
        $stagedUpdaterArchiveSha256 = (Get-FileHash -LiteralPath $updaterArchive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($UpdaterRelease) {
            $updaterSignaturePath = "$($updaterArchive.FullName).sig"
            if (Test-Path -LiteralPath $updaterSignaturePath) {
                throw "Refusing to overwrite an existing updater signature: $updaterSignaturePath"
            }
            # Sign only the verified safe-basename copy. The original Tauri archive
            # and setup.exe remain untouched; --no-sign keeps Authenticode disabled.
            $signerArgs = @('run', 'tauri', '--', 'signer', 'sign', '--app-version', $updaterVersion, $updaterArchive.FullName)
            $oldErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & $npm.Source @signerArgs 2>&1
                $signerExitCode = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $oldErrorActionPreference
            }
            if ($signerExitCode -ne 0) {
                throw "Signing the NSIS updater archive failed (exit code $signerExitCode)."
            }
            if (-not (Test-Path -LiteralPath $updaterSignaturePath -PathType Leaf) -or
                (Get-Item -LiteralPath $updaterSignaturePath).Length -le 0) {
                throw 'Tauri signer did not create the NSIS updater archive .sig.'
            }
            $updaterSignature = Get-Item -LiteralPath $updaterSignaturePath
        } else {
            Write-Output 'Updater archive staged without a signature; host signing is required before release.'
        }
    }
    # Filtered source archives do not carry .git metadata, and build hosts may
    # not have Git installed. Treat provenance as unavailable in either case
    # instead of letting PowerShell's Stop preference abort after packaging.
    $commit = 'unknown'
    $dirty = $true
    $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
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
        noticeInventory = $payloadManifest.noticeInventory
    }
    if ($updaterArtifacts) {
        $packageManifest.updaterArtifact = [ordered]@{
            target = 'windows-x86_64-nsis'
            version = $updaterVersion
            name = $updaterArchive.Name
            length = $updaterArchive.Length
            sha256 = $stagedUpdaterArchiveSha256
            originalTauriArchiveName = $originalUpdaterArchive.Name
            originalTauriArchiveLength = $originalUpdaterArchiveLength
            originalTauriArchiveSha256 = $originalUpdaterArchiveSha256
            signatureStatus = if ($UpdaterRelease) { 'signed' } else { 'not_signed' }
        }
        if ($UpdaterRelease) {
            $packageManifest.updaterArtifact.signatureName = $updaterSignature.Name
            $packageManifest.updaterArtifact.signatureLength = $updaterSignature.Length
            $packageManifest.updaterArtifact.signatureSha256 = (Get-FileHash -LiteralPath $updaterSignature.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $packageManifest.updaterArtifact.signatureVersionBinding = 'Tauri signer --app-version; signature not independently verified by this package helper'
        } else {
            $packageManifest.updaterArtifact.signatureAvailability = 'host signing required before update installation is available'
        }
    }
    $manifestPath = "$($installer.FullName).manifest.json"
    $packageManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Output "Unsigned per-user installer: $($installer.FullName)"
    Write-Output "SHA-256: $hash"
    Write-Output "Manifest: $manifestPath"
    if ($updaterArtifacts) {
        Write-Output "Staged Tauri NSIS updater archive: $($updaterArchive.FullName)"
        if ($UpdaterRelease) {
            Write-Output "Updater signature: $($updaterSignature.FullName)"
        }
    }
    Write-Output 'The installer has not been run or Authenticode-signed.'
} finally {
    if ($versionOverlayPath -and (Test-Path -LiteralPath $versionOverlayPath)) {
        Remove-Item -LiteralPath $versionOverlayPath -Force
    }
    Pop-Location
}
