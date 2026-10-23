$ErrorActionPreference = 'Stop'

# Provision only the toolchain needed by the portable Windows Rust test suite.
# Run from an elevated PowerShell session. This does not touch Windows accounts,
# activation, repository contents, or system PATH.

function Assert-ExitCode([string] $Label, [int] $Code) {
    if ($Code -eq 3010) {
        Write-Host "$Label completed; Windows reports that a reboot is required (3010)."
        $script:RebootRequired = $true
        return
    }
    if ($Code -ne 0) {
        Write-Error "$Label failed with exit code $Code" -ErrorAction Continue
        exit $Code
    }
}

function Invoke-Installer([string] $FilePath, [string[]] $Arguments, [string] $Label) {
    $logName = $Label -replace '[^A-Za-z0-9_.-]', '_'
    $stdoutLog = Join-Path $script:InstallerLogDir "$logName.stdout.log"
    $stderrLog = Join-Path $script:InstallerLogDir "$logName.stderr.log"
    Remove-Item -LiteralPath $stdoutLog, $stderrLog -Force -ErrorAction SilentlyContinue
    Write-Host "Running $Label..."
    Write-Host "Installer output: $stdoutLog ; $stderrLog"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
        foreach ($logPath in @($stdoutLog, $stderrLog)) {
            if (Test-Path -LiteralPath $logPath) {
                Write-Host "Last installer output from ${logPath}:"
                Get-Content -LiteralPath $logPath -Tail 80 | ForEach-Object { Write-Host $_ }
            }
        }
    }
    Assert-ExitCode $Label $process.ExitCode
}

function Get-VsWherePath {
    $candidate = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }
    return $null
}

function Test-MsvcAndWindowsSdk {
    $script:SelectedWindowsSdk = $null
    $vswhere = Get-VsWherePath
    if (-not $vswhere) {
        return $false
    }

    $installPath = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $installPath) {
        return $false
    }
    if (-not (Test-Path -LiteralPath (Join-Path $installPath 'VC\Tools\MSVC'))) {
        return $false
    }

    $sdkInclude = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
    if (-not (Test-Path -LiteralPath $sdkInclude)) {
        return $false
    }
    $sdkVersions = Get-ChildItem -LiteralPath $sdkInclude -Directory -ErrorAction SilentlyContinue
    foreach ($version in $sdkVersions) {
        $header = Join-Path $version.FullName 'um\Windows.h'
        $library = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib\$($version.Name)\um\x64\kernel32.lib"
        $cfApiHeader = Join-Path $version.FullName 'um\CfApi.h'
        $cldApiLibrary = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib\$($version.Name)\um\x64\CldApi.lib"
        if ((Test-Path -LiteralPath $header -PathType Leaf) -and
            (Test-Path -LiteralPath $library -PathType Leaf) -and
            (Test-Path -LiteralPath $cfApiHeader -PathType Leaf) -and
            (Test-Path -LiteralPath $cldApiLibrary -PathType Leaf)) {
            $script:SelectedWindowsSdk = [ordered]@{
                version = $version.Name
                windows_header = $header
                kernel32_library = $library
                cfapi_header = $cfApiHeader
                cldapi_library = $cldApiLibrary
            }
            return $true
        }
    }
    return $false
}

function Install-MsvcAndWindowsSdk {
    if (Test-MsvcAndWindowsSdk) {
        Write-Host 'Visual Studio C++ build tools and a Windows SDK are already installed.'
        return
    }

    $tempInstaller = Join-Path ([System.IO.Path]::GetTempPath()) 'raiun-vs_BuildTools.exe'
    try {
        Write-Host 'Downloading the official Visual Studio Build Tools bootstrapper...'
        Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $tempInstaller
        $signature = Get-AuthenticodeSignature -FilePath $tempInstaller
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
            throw 'The Visual Studio bootstrapper signature could not be verified as Microsoft-signed.'
        }

        $installPath = $null
        $vswhere = Get-VsWherePath
        if ($vswhere) {
            $installPath = (& $vswhere -latest -products '*' -property installationPath | Select-Object -First 1)
            if ($LASTEXITCODE -ne 0) {
                $installPath = $null
            }
        }

        $arguments = @('--quiet', '--wait', '--norestart', '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended')
        if ($installPath) {
            $arguments += @('--installPath', "`"$installPath`"")
        }
        Invoke-Installer $tempInstaller $arguments 'Visual Studio Build Tools C++ workload and recommended Windows SDK'
    } finally {
        Remove-Item -LiteralPath $tempInstaller -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-MsvcAndWindowsSdk) -and -not $script:RebootRequired) {
        throw 'The installer completed, but MSVC C++ tools and a Windows SDK were not detected. Review the Visual Studio Installer log.'
    }
    if (-not (Test-MsvcAndWindowsSdk)) {
        Write-Warning 'Visual Studio reports a pending reboot; confirm the tools after restarting Windows.'
    }
}

function Install-RustMsvcToolchain {
    $rustup = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    $rustBin = Split-Path -Parent $rustup
    if (-not (($env:PATH -split ';') -contains $rustBin)) {
        $env:PATH = "$rustBin;$env:PATH"
    }
    if (-not (Test-Path -LiteralPath $rustup)) {
        $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "raiun-rustup-$PID-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
        $tempInstaller = Join-Path $tempDirectory 'rustup-init.exe'
        $tempChecksum = Join-Path $tempDirectory 'rustup-init.exe.sha256'
        try {
            Write-Host 'Downloading the official Rustup installer...'
            $rustupUrl = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
            Invoke-WebRequest -UseBasicParsing -Uri $rustupUrl -OutFile $tempInstaller
            Invoke-WebRequest -UseBasicParsing -Uri "$rustupUrl.sha256" -OutFile $tempChecksum
            $checksumText = Get-Content -LiteralPath $tempChecksum -Raw
            $expectedHash = [regex]::Match($checksumText, '(?i)\b([a-f0-9]{64})\b').Groups[1].Value
            if (-not $expectedHash) {
                throw 'The official Rustup SHA-256 sidecar did not contain a valid checksum.'
            }
            $actualHash = (Get-FileHash -LiteralPath $tempInstaller -Algorithm SHA256).Hash
            if ($actualHash -ne $expectedHash) {
                throw 'The Rustup installer SHA-256 does not match the official sidecar.'
            }
            Invoke-Installer $tempInstaller @('-y', '--default-host', 'x86_64-pc-windows-msvc', '--default-toolchain', 'none', '--profile', 'minimal', '--no-modify-path') 'Rustup'
        } finally {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host 'Rustup is already installed for this Windows user.'
    }

    if (-not (Test-Path -LiteralPath $rustup)) {
        throw "Rustup did not create the expected executable at $rustup"
    }
    Invoke-Installer $rustup @('toolchain', 'install', 'stable-x86_64-pc-windows-msvc', '--profile', 'minimal') 'Rust stable MSVC toolchain'
    Invoke-Installer $rustup @('default', 'stable-x86_64-pc-windows-msvc') 'Rust default toolchain selection'
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this provisioning script from an elevated PowerShell session.'
}

$script:RebootRequired = $false
$script:InstallerLogDir = Join-Path $env:TEMP 'raiun-windows-toolchain-logs'
New-Item -ItemType Directory -Path $script:InstallerLogDir -Force | Out-Null
Install-MsvcAndWindowsSdk
Install-RustMsvcToolchain

$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
$rustc = Join-Path $env:USERPROFILE '.cargo\bin\rustc.exe'
if (-not (Test-Path -LiteralPath $cargo) -or -not (Test-Path -LiteralPath $rustc)) {
    throw 'Rust tools were not found in the expected per-user Rustup directory.'
}
$rustcVersion = (& $rustc -vV) -join "`n"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
if ($rustcVersion -notmatch 'host: x86_64-pc-windows-msvc') {
    throw 'The active Rust compiler is not targeting x86_64-pc-windows-msvc.'
}

if ($script:SelectedWindowsSdk) {
    Write-Host ('Qualified Windows SDK: ' + ($script:SelectedWindowsSdk | ConvertTo-Json -Compress))
}
Write-Host 'Windows test toolchain is ready.'
Write-Host "Rust tools: $env:USERPROFILE\.cargo\bin (no PATH changes made)"
Write-Host 'Open Developer PowerShell for Visual Studio before running scripts/test-windows-vm.ps1.'
if ($script:RebootRequired) {
    exit 3010
}
exit 0
