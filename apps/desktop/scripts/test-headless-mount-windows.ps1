# Explicit native synthetic mount acceptance on an authorized disposable PC.
# No installs, real accounts, autostart, firewall changes, forced process stops,
# recursive deletion, or registry/provider cleanup are performed by this runner.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativeReadFixture,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(60,1800)][int]$TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
# Recent PowerShell/.NET versions retain an empty environment entry when passed
# $null. Rust distinguishes an absent phase/config variable from an empty one.
function Set-FixtureProcessEnvironment([string]$Name, [AllowNull()][object]$Value) {
    if ($null -eq $Value) {
        $path = 'Env:' + $Name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -ErrorAction Stop }
    } else {
        [Environment]::SetEnvironmentVariable($Name, [string]$Value, 'Process')
    }
}
if (-not $RunNativeReadFixture) { throw 'This test really registers a temporary Cloud Files root. Pass -RunNativeReadFixture only on the explicitly authorized disposable Windows machine.' }
$test = 'agent_windows::windows_profiles::windows_headless_mount_test::synthetic_headless_personal_and_space_hydration'
$executable = (Get-Item -LiteralPath $AgentTestExecutable).FullName
if ((Get-Item -LiteralPath $executable).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The test executable must be an ordinary hash-verified file.' }
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Test executable checksum mismatch; nothing was launched.' }
$parent = (Get-Item -LiteralPath $OutputParent).FullName
if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose an ordinary local evidence parent directory.' }
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Native fixture needs a fixed local NTFS test directory.' }
$directory = Join-Path $parent ('raiun-headless-native-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-native-mount-v1`n")
$receipt = [ordered]@{ fixture='headless-native-read-v1'; test=$test; test_executable_sha256=$ExpectedSha256.ToLowerInvariant();
    native_opt_in=$true; evidence=$directory; started_utc=[DateTime]::UtcNow.ToString('o');
    powershell=$PSVersionTable.PSVersion.ToString(); startup_changed=$false; real_accounts_used=$false;
    registration_cleanup='not attempted; root/state retained; disconnect status is recorded by the fixture' }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_NATIVE_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD=$null
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
Write-Output "Native synthetic fixture PID $($process.Id); evidence: $directory"
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $receipt['timeout']=$true; $receipt['supervisor_pid']=$process.Id
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Native fixture is still running after timeout. No process was killed and no root/state was deleted. Preserve PID $($process.Id) and evidence at $directory for safe-disconnect investigation."
}
$process.Refresh()
$receipt['supervisor_exit_code']=$process.ExitCode
$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Native fixture failed. Root, registrations and all evidence are preserved at $directory; inspect stages and child logs. No hydration fallback or forced cleanup was attempted." }
$resultsPath = Join-Path $directory 'RESULTS.json'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw 'The exact test produced no result receipt; do not count this as acceptance.' }
$results = Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json
if (-not $results.passed -or $results.phases.Count -ne 2 -or $results.mutation_attempt_count -ne 0) { throw 'Fixture receipts do not establish complete read/restart acceptance.' }
Write-Output 'Synthetic headless Personal+Space ordinary reads, safe unmount and saved-session restart passed. Disconnected root/registration/state are retained for review.'
Write-Output 'This does not establish writes, boot Session 0, Server Core, real-server or GUI coexistence acceptance.'
Write-Output "Evidence: $directory"
