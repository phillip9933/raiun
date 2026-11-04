$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $cargo = Get-Command cargo.exe -ErrorAction Stop
    $rustc = Get-Command rustc.exe -ErrorAction Stop
    $toolchain = (& $rustc.Source -vV) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not query the active Rust toolchain.'
    }
    if ($toolchain -notmatch 'host: x86_64-pc-windows-msvc') {
        throw 'Windows installer payloads must be built with the x86_64-pc-windows-msvc toolchain.'
    }

    $cl = Get-Command cl.exe -ErrorAction Stop
    $link = Get-Command link.exe -ErrorAction Stop
    if ($cl.Source -notlike '*\VC\Tools\MSVC\*' -or $link.Source -notlike '*\VC\Tools\MSVC\*') {
        throw 'Run from a Visual Studio Developer PowerShell with the MSVC compiler and linker available.'
    }

    # BEGIN payload Cargo target resolver
    $payloadTargetDir = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        Join-Path $repoRoot 'target'
    } elseif ([System.IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) {
        [System.IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $env:CARGO_TARGET_DIR))
    }
    # END payload Cargo target resolver

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $cargo.Source build --locked --release --target x86_64-pc-windows-msvc --target-dir $payloadTargetDir -p raiun-agent -p raiun-cli 2>&1
        $buildExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($buildExitCode -ne 0) {
        throw "Building the Windows agent and CLI failed (exit code $buildExitCode)."
    }

    $sourceDir = Join-Path $payloadTargetDir 'x86_64-pc-windows-msvc\release'
    $stageDir = Join-Path $repoRoot 'target\windows-package-resources'
    $windowsLegalDir = Join-Path $repoRoot 'legal\windows'
    $inventoryPath = Join-Path $windowsLegalDir 'dependency-inventory.json'
    $requiredNotices = @(
        (Join-Path $repoRoot 'LICENSE'),
        (Join-Path $repoRoot 'NOTICE'),
        (Join-Path $windowsLegalDir 'THIRD-PARTY-NOTICES.md'),
        $inventoryPath
    )
    foreach ($noticePath in $requiredNotices) {
        if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
            throw "Required Windows redistribution notice is missing: $noticePath"
        }
    }
    $noticeInventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
    function Assert-NoticeRecord {
        param($Record, [string] $Description, [switch] $RequireWindowsLegalPath)
        if ($null -eq $Record -or [string]::IsNullOrWhiteSpace([string] $Record.path) -or
            $null -eq $Record.bytes -or [long] $Record.bytes -lt 0 -or
            [string] $Record.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Windows notice record is incomplete: $Description"
        }
        $path = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Record.path))
        $base = if ($RequireWindowsLegalPath) { [System.IO.Path]::GetFullPath($windowsLegalDir) } else { [System.IO.Path]::GetFullPath($repoRoot) }
        if (-not $path.StartsWith($base + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Windows notice file is missing or outside its permitted source folder: $Description ($($Record.path))"
        }
        $actual = Get-Item -LiteralPath $path
        if ([long] $actual.Length -ne [long] $Record.bytes) {
            throw "Windows notice length mismatch: $Description ($($Record.path))"
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne ([string] $Record.sha256).ToLowerInvariant()) {
            throw "Windows notice SHA-256 mismatch: $Description ($($Record.path))"
        }
        return $path
    }
    if ($noticeInventory.target -cne 'x86_64-pc-windows-msvc') {
        throw 'Windows redistribution notice inventory target does not match the MSVC package target.'
    }
    $expectedLockPaths = @('Cargo.lock', 'desktop-shell/src-tauri/Cargo.lock', 'package-lock.json', 'desktop-shell/package-lock.json')
    $recordedLockPaths = @($noticeInventory.lock_sha256.PSObject.Properties.Name)
    if ($recordedLockPaths.Count -ne $expectedLockPaths.Count) {
        throw 'Windows notice inventory lock hash set is incomplete or unexpected.'
    }
    foreach ($lockPath in $expectedLockPaths) {
        $recordedHash = [string] $noticeInventory.lock_sha256.PSObject.Properties[$lockPath].Value
        if ($recordedHash -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Windows notice inventory lock hash is missing or malformed: $lockPath"
        }
        $actualLockPath = Join-Path $repoRoot $lockPath
        if (-not (Test-Path -LiteralPath $actualLockPath -PathType Leaf)) {
            throw "Windows notice inventory lock file is missing: $lockPath"
        }
        $actualLockHash = (Get-FileHash -LiteralPath $actualLockPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualLockHash -cne $recordedHash.ToLowerInvariant()) {
            throw "Windows notice inventory lock hash mismatch: $lockPath"
        }
    }
    $requiredNoticeRecords = @('LICENSE', 'NOTICE', 'legal/windows/THIRD-PARTY-NOTICES.md')
    $firstPartyRecords = @($noticeInventory.first_party_notice_files)
    foreach ($requiredPath in $requiredNoticeRecords) {
        $matchingRecords = @($firstPartyRecords | Where-Object path -CEQ $requiredPath)
        if ($matchingRecords.Count -ne 1) {
            throw "Windows first-party notice hash record is missing or duplicated: $requiredPath"
        }
        Assert-NoticeRecord -Record $matchingRecords[0] -Description $requiredPath | Out-Null
    }
    if (@($noticeInventory.gaps).Count -gt 0) {
        throw "Windows package has unresolved dependency notice gaps; refusing to stage payloads. See $inventoryPath"
    }
    $externalReview = @($noticeInventory.bundled_external_artifact_review)
    if (@($externalReview | Where-Object artifact -CEQ 'WebView2Loader.dll').Count -ne 1) {
        throw 'Windows notice inventory must review the bundled WebView2Loader.dll exactly once.'
    }
    foreach ($artifact in $externalReview) {
        if ($artifact.status -cne 'verified') {
            throw "Bundled third-party binary has unresolved redistribution review: $($artifact.artifact)"
        }
        foreach ($field in @('license_file', 'notice_file', 'nuspec')) {
            Assert-NoticeRecord -Record $artifact.$field -Description "$($artifact.artifact) $field" -RequireWindowsLegalPath | Out-Null
        }
        Assert-NoticeRecord -Record $artifact.package_provenance -Description "$($artifact.artifact) package provenance" -RequireWindowsLegalPath | Out-Null
        $sdkProvenance = Get-Content -LiteralPath (Join-Path $repoRoot $artifact.package_provenance.path) -Raw | ConvertFrom-Json
        if ($sdkProvenance.nuget_version -cne $artifact.sdk_version -or
            $sdkProvenance.nuget_nupkg_sha256 -cne $artifact.nuget_package_sha256 -or
            [long] $sdkProvenance.nuget_nupkg_bytes -ne [long] $artifact.nuget_package_bytes -or
            $sdkProvenance.x64_loader_sha256 -cne $artifact.loader_sha256) {
            throw "Bundled binary SDK provenance mismatch: $($artifact.artifact)"
        }
    }
    foreach ($package in @($noticeInventory.rust_packages) + @($noticeInventory.production_ui_packages)) {
        foreach ($text in @($package.notice_files)) {
            Assert-NoticeRecord -Record $text -Description "$($package.name) dependency notice" -RequireWindowsLegalPath | Out-Null
        }
    }
    foreach ($text in @($noticeInventory.eme_notice) + @($noticeInventory.rust_toolchain_notices) + @($noticeInventory.supplemental_build_tool_notices | ForEach-Object { $_.notice_files })) {
        if ($null -eq $text.path) { continue }
        Assert-NoticeRecord -Record $text -Description 'Windows runtime or build-tool notice' -RequireWindowsLegalPath | Out-Null
    }
    $noticeFiles = @($requiredNotices | ForEach-Object {
        [pscustomobject]@{
            path = $_.Substring($repoRoot.Length + 1).Replace('\', '/')
            length = (Get-Item -LiteralPath $_).Length
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
    $noticeFiles += @(Get-ChildItem -LiteralPath $windowsLegalDir -File -Recurse | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{
            path = $_.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
            length = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
    $tempDir = Join-Path $repoRoot ("target\windows-package-resources.tmp-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    try {
        $payloads = @('raiun-agent.exe', 'raiun.exe')
        $records = @()
        foreach ($name in $payloads) {
            $source = Join-Path $sourceDir $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Required Windows payload was not produced: $name"
            }
            $target = Join-Path $tempDir $name
            Copy-Item -LiteralPath $source -Destination $target
            $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            $records += [pscustomobject]@{
                name = $name
                length = (Get-Item -LiteralPath $target).Length
                sha256 = $hash
            }
        }

        $manifest = [ordered]@{
            format = 'raiun-windows-payload-v2'
            target = 'x86_64-pc-windows-msvc'
            signed = $false
            payloads = $records
            noticeInventory = [ordered]@{
                target = $noticeInventory.target
                sha256 = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant()
                files = $noticeFiles
            }
        }
        $manifestPath = Join-Path $tempDir 'payload-manifest.json'
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        if (Test-Path -LiteralPath $stageDir) {
            Remove-Item -LiteralPath $stageDir -Recurse -Force
        }
        Move-Item -LiteralPath $tempDir -Destination $stageDir
    } finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force
        }
    }

    Write-Output "Prepared x86_64 MSVC installer resources at $stageDir"
    Get-Content -LiteralPath (Join-Path $stageDir 'payload-manifest.json')
} finally {
    Pop-Location
}
