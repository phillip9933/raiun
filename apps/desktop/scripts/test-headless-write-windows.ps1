# Explicit synthetic ordinary-write acceptance on the authorized disposable PC.
# No installs, real accounts, startup changes, forced stops, unregister or deletion.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativeWriteFixture,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(60,1800)][int]$TimeoutSeconds = 420
)
$ErrorActionPreference = 'Stop'
# Preserve absent versus empty environment values on recent PowerShell/.NET.
function Set-FixtureProcessEnvironment([string]$Name, [AllowNull()][object]$Value) {
    if ($null -eq $Value) {
        $path = 'Env:' + $Name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -ErrorAction Stop }
    } else {
        [Environment]::SetEnvironmentVariable($Name, [string]$Value, 'Process')
    }
}
if (-not $RunNativeWriteFixture) { throw 'This test registers three temporary Cloud Files roots and writes synthetic files. Pass -RunNativeWriteFixture only on the explicitly authorized disposable Windows machine.' }
$test = 'agent_windows::windows_profiles::windows_headless_write_test::synthetic_headless_ordinary_save_and_failures'
$executable = (Get-Item -LiteralPath $AgentTestExecutable).FullName
if ((Get-Item -LiteralPath $executable).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The test executable must be an ordinary hash-verified file.' }
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Test executable checksum mismatch; nothing was launched.' }
$parent = (Get-Item -LiteralPath $OutputParent).FullName
if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose an ordinary local evidence parent directory.' }
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Native write fixture needs a fixed local NTFS evidence directory.' }
$directory = Join-Path $parent ('raiun-headless-write-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-native-write-v1`n")
$receipt = [ordered]@{ fixture='headless-native-write-v1'; test=$test; test_executable_sha256=$ExpectedSha256.ToLowerInvariant();
    native_opt_in=$true; evidence=$directory; started_utc=[DateTime]::UtcNow.ToString('o');
    powershell=$PSVersionTable.PSVersion.ToString(); startup_changed=$false; real_accounts_used=$false;
    registration_cleanup='not attempted; roots/edits/state retained; disconnect status is recorded by the fixture' }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_WRITE_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_WRITE_FIXTURE_CHILD=$null
    RAIUN_HEADLESS_CONTEXT=$null
    RAIUN_HEADLESS_CONFIG=$null
    RAIUN_STATE_DIR=$null
}
$previous = @{}
try {
    foreach ($name in $changes.Keys) {
        $previous[$name] = @{
            present = [Environment]::GetEnvironmentVariables('Process').Contains($name)
            value = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        Set-FixtureProcessEnvironment $name $changes[$name]
    }
    $process = Start-Process -FilePath $executable -ArgumentList @('--ignored','--exact',$test,'--nocapture','--test-threads=1') -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $directory 'supervisor.stdout.log') -RedirectStandardError (Join-Path $directory 'supervisor.stderr.log')
} finally {
    foreach ($name in $previous.Keys) {
        $saved = $previous[$name]
        if ($saved.present) { Set-FixtureProcessEnvironment $name $saved.value }
        else { Set-FixtureProcessEnvironment $name $null }
    }
}
Write-Output "Native synthetic write fixture PID $($process.Id); evidence: $directory"
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $receipt['timeout']=$true; $receipt['supervisor_pid']=$process.Id
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Fixture remains running after timeout. No process was killed or root/state deleted. Preserve PID $($process.Id) and evidence at $directory for normal-disconnect investigation."
}
$process.Refresh()
$receipt['supervisor_exit_code']=$process.ExitCode
$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Native write fixture failed. All roots, registrations, edited bytes, DPAPI state and logs remain at $directory. No forced cleanup was attempted." }
$resultsPath = Join-Path $directory 'RESULTS.json'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw 'No exact result receipt; do not claim native write acceptance.' }
$results = Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json
if (-not $results.passed -or $results.fixture -cne 'headless-native-write-v1' -or $results.scenarios.Count -ne 3) { throw 'Receipts do not establish all three native write scenarios.' }
$names = @($results.scenarios | ForEach-Object { $_.scenario } | Sort-Object)
if (($names -join ',') -cne 'forbidden,success,unavailable') { throw 'Unexpected or duplicated scenario receipt.' }
foreach ($case in $results.scenarios) {
    if (-not $case.passed -or -not $case.child.passed -or -not $case.child.safe_unmount -or -not $case.child.normal_shutdown -or -not $case.child.exact_registration_retained -or -not $case.child.dpapi_journal_retained_after_disconnect -or -not $case.child.edited_bytes_retained_after_disconnect -or $case.child.folder_generation -ne 0) { throw 'A scenario lacks safe-disconnect, retention or disabled-sync evidence.' }
}
Write-Output 'Synthetic ordinary Space save, explicit 403 refusal and unavailable transport before dispatch passed. Every registration, edited file and private journal remains retained.'
Write-Output 'This does not establish Personal writes, busy-unmount, startup, real-server, permission-UI or encrypted-write acceptance.'
Write-Output "Evidence: $directory"
