param(
    [string]$SigningDirectory = "$env:USERPROFILE/.android/opencloud-next-release",
    [string]$SdkPath = "$env:LOCALAPPDATA/Android/Sdk"
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$inputApk = Join-Path $repo 'app/build/outputs/apk/release/app-release-unsigned.apk'
$config = [IO.File]::ReadAllText((Join-Path $repo 'app/build/generated/source/buildConfig/release/eu/opencloud/android/next/BuildConfig.java'))
if ([regex]::Matches($config, 'DEV_SERVER_(URL|USERNAME|PASSWORD)\s*=\s*"";').Count -ne 3) { throw 'Development credentials must be empty.' }
if ($config -notmatch 'VERSION_NAME = "([0-9A-Za-z.-]+)"') { throw 'Missing version name.' }
$version = $Matches[1]
if ($config -notmatch 'DEBUG = false') { throw 'Release must not be debuggable.' }
$outDir = Join-Path $repo 'app/build/outputs/apk/published'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outputApk = Join-Path $outDir "raiun-$version.apk"
$tools = Join-Path $SdkPath 'build-tools/36.0.0'
$credential = Import-Clixml -LiteralPath (Join-Path $SigningDirectory 'password.clixml')
try {
    $env:OPENCLOUD_RELEASE_STORE_PASSWORD = $credential.GetNetworkCredential().Password
    & "$tools/apksigner.bat" sign --ks (Join-Path $SigningDirectory 'release.p12') --ks-key-alias opencloud-next --ks-pass env:OPENCLOUD_RELEASE_STORE_PASSWORD --key-pass env:OPENCLOUD_RELEASE_STORE_PASSWORD --out $outputApk $inputApk
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
} finally { Remove-Item Env:OPENCLOUD_RELEASE_STORE_PASSWORD -ErrorAction SilentlyContinue }
$verification = & "$tools/apksigner.bat" verify --verbose --print-certs $outputApk
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed.' }
$publicPem = [IO.File]::ReadAllText((Join-Path $repo 'docs/release-certificate.pem'))
$publicDer = [Convert]::FromBase64String(($publicPem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''))
$expectedSigner = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($publicDer)).ToLowerInvariant()
$verifiedText = $verification -join "`n"
if ($verifiedText -notmatch "Signer #1 certificate SHA-256 digest: $expectedSigner" -or $verifiedText -notmatch 'Number of signers: 1(?:\r?\n|$)') {
    throw 'Signing identity differs from the published release certificate. Do not distribute this APK.'
}
Write-Output $verification
& "$tools/zipalign.exe" -c -P 16 4 $outputApk
if ($LASTEXITCODE -ne 0) { throw '16-KiB alignment verification failed.' }
$hash = (Get-FileHash -LiteralPath $outputApk -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $outDir 'SHA256SUMS'), "$hash  $([IO.Path]::GetFileName($outputApk))`n")
Write-Output "Verified release APK: $outputApk"
