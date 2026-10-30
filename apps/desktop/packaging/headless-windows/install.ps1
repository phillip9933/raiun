param([string]$Destination = (Join-Path $env:LOCALAPPDATA 'RaiunHeadlessCLI'))
$ErrorActionPreference = 'Stop'
if ($Destination -notmatch '^[A-Za-z]:[\\/]') { throw 'Choose an absolute new local install directory.' }
$Destination = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $Destination) { throw 'Existing install preserved. Choose a new destination.' }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach ($name in @('raiun.exe', 'raiun-agent.exe')) {
    $expected = $manifest.files.$name
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw 'Invalid candidate manifest.' }
    $file = Get-Item -LiteralPath (Join-Path $PSScriptRoot $name)
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Invalid candidate payload.' }
    if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ine $expected) { throw 'Candidate checksum mismatch.' }
}
New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
foreach ($name in @('raiun.exe','raiun-agent.exe','README.md','manifest.json','SHA256SUMS','LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','PRIVACY.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $Destination
}
foreach ($name in @('HEADLESS.md', 'HEADLESS-WINDOWS.md', 'HEADLESS-STARTUP.md', 'startup.ps1')) {
    $optional = Join-Path $PSScriptRoot $name
    if (Test-Path -LiteralPath $optional -PathType Leaf) { Copy-Item -LiteralPath $optional -Destination $Destination }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'legal') -Destination $Destination -Recurse
Write-Output "Installed local headless candidate to $Destination"
Write-Output 'No service, autostart, PATH, account or provider registration was changed.'
$quotedCli = (Join-Path $Destination 'raiun.exe').Replace("'", "''")
Write-Output "After configuring remembered login and auto_mount, preview boot startup:"
Write-Output "& '$quotedCli' --config C:\RaiunCli\config.json drive --state-dir C:\RaiunCli\state startup enable --dry-run"
Write-Output 'Remove --dry-run only when ready. Boot registration requires an elevated terminal under the same Windows account and prompts for its password; no password is accepted in argv.'
