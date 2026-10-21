$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    $rustc = Join-Path $env:USERPROFILE '.cargo\bin\rustc.exe'
    if (-not (Test-Path -LiteralPath $cargo) -or -not (Test-Path -LiteralPath $rustc)) {
        throw 'Install Rust with scripts/provision-windows-test-tools.ps1 or provide the per-user Rustup binaries.'
    }
    $rustBin = Split-Path -Parent $cargo
    if (-not (($env:PATH -split ';') -contains $rustBin)) {
        $env:PATH = "$rustBin;$env:PATH"
    }
    $clPath = (Get-Command cl.exe -ErrorAction Stop).Source
    $linkPath = (Get-Command link.exe -ErrorAction Stop).Source
    if ($clPath -notmatch '\\VC\\Tools\\MSVC\\' -or $linkPath -notmatch '\\VC\\Tools\\MSVC\\') {
        throw 'Open Developer PowerShell for Visual Studio so the MSVC compiler and linker are on PATH'
    }

    $rustcDetails = (& $rustc -vV) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not query the active Rust toolchain (exit code $LASTEXITCODE)"
    }
    if ($rustcDetails -notmatch 'host: x86_64-pc-windows-msvc') {
        throw 'Use the stable x86_64-pc-windows-msvc Rust toolchain for this VM test'
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $cargo test --locked -p raiun-core -p raiun-cli -p raiun-opencloud -p raiun-engine -p raiun-vault
        $cargoExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($cargoExitCode -ne 0) {
        throw "Portable Rust tests failed with exit code $cargoExitCode"
    }
} finally {
    Pop-Location
}
