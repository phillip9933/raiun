$ErrorActionPreference = 'Stop'

$installer = Join-Path $PSScriptRoot 'install_offline_scanner_sdk.py'
$pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pythonLauncher) {
    & $pythonLauncher.Source -3 $installer
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $pythonCommand) { throw 'Python 3 is required. Install Python 3 and rerun this script.' }
    & $pythonCommand.Source $installer
}
if ($LASTEXITCODE -ne 0) {
    throw "Scanner SDK installation failed with exit code $LASTEXITCODE."
}
