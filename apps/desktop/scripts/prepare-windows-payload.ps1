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
            format = 'raiun-windows-payload-v1'
            target = 'x86_64-pc-windows-msvc'
            signed = $false
            payloads = $records
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
