param(
    [string]$SdkPath = "$env:LOCALAPPDATA/Android/Sdk",
    [string]$BuildToolsVersion = "36.0.0",
    [string]$TestKeystore = "$env:USERPROFILE/.android/debug.keystore"
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$unsignedApk = Join-Path $repository 'app/build/outputs/apk/release/app-release-unsigned.apk'
$releaseConfig = Join-Path $repository 'app/build/generated/source/buildConfig/release/eu/opencloud/android/next/BuildConfig.java'
$signer = Join-Path $SdkPath "build-tools/$BuildToolsVersion/apksigner.bat"
$outputDirectory = Join-Path $repository 'app/build/outputs/apk/testing'
$outputApk = Join-Path $outputDirectory 'opencloud-next-test.apk'

foreach ($required in @($unsignedApk, $releaseConfig, $signer, $TestKeystore)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required packaging input is missing: $required" }
}
$configuration = [IO.File]::ReadAllText($releaseConfig)
$emptyFields = [regex]::Matches($configuration, 'DEV_SERVER_(URL|USERNAME|PASSWORD)\s*=\s*"";').Count
if ($emptyFields -ne 3) { throw 'Release development credentials must all be empty before packaging.' }

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
& $signer sign --ks $TestKeystore --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out $outputApk $unsignedApk
if ($LASTEXITCODE -ne 0) { throw 'Test APK signing failed.' }
& $signer verify $outputApk
if ($LASTEXITCODE -ne 0) { throw 'Test APK signature verification failed.' }
Get-FileHash -LiteralPath $outputApk -Algorithm SHA256
Write-Output "Installable test build: $outputApk"
Write-Output 'Signed with the local Android debug certificate. This is not a production release signature.'
