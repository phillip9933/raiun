# Explicit synthetic saved-edit recovery on the authorized disposable Windows PC.
# No install, real account, startup change, forced stop, unregister or deletion.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativeEditsFixture,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(60,1800)][int]$TimeoutSeconds = 420
)
$ErrorActionPreference = 'Stop'
function Set-FixtureProcessEnvironment([string]$Name, [AllowNull()][object]$Value) {
    if ($null -eq $Value) {
        # Setting null can retain an empty key on recent PowerShell/.NET.
        $path = 'Env:' + $Name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -ErrorAction Stop }
    } else {
        [Environment]::SetEnvironmentVariable($Name, [string]$Value, 'Process')
    }
}
function Assert-OrdinaryPath([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ([bool]$item.PSIsContainer -ne $Directory) { throw 'Unexpected fixture path type.' }
    $cursor = $item
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Fixture paths and ancestors must not be reparse points.' }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory } else { $cursor = $cursor.Parent }
    }
    return $item.FullName
}
function Assert-RecoveryResults($Results) {
    if ($Results.fixture -cne 'headless-edits-native-v1' -or $Results.passed -ne $true -or
        $Results.ordinary_space_only -ne $true -or $Results.unregister_attempted -ne $false -or
        $Results.old_generation_completion_supported -ne $false -or $Results.global_mutation_attempts -ne 2) {
        throw 'Exact receipts do not establish the bounded ordinary saved-edit recovery scenario.'
    }
    $child = $Results.child
    if ($child.passed -ne $true -or $child.safe_unmount -ne $true -or $child.normal_stop -ne $true -or $child.root_state_retained -ne $true) {
        throw 'Missing native recovery, normal-disconnect or retained-state evidence.'
    }
    foreach ($name in @('pending_403_detected','stale_generation_and_scope_no_remote_io','wrong_path_retains','exact_path_completed','native_and_journal_completion_required')) {
        if ($child.detail.$name -ne $true) { throw "Missing recovery assertion receipt: $name" }
    }
    if ($Results.remote.put_attempt_count -ne 2 -or $Results.remote.put_count -ne 1 -or $Results.remote.forbidden_put_count -ne 1) {
        throw 'Expected one refused PUT and one successful conditional recovery PUT, without replay.'
    }
}
if (-not $RunNativeEditsFixture) { throw 'This test registers a temporary Cloud Files root, writes synthetic bytes, receives a synthetic 403 and explicitly recovers the saved edit. Pass -RunNativeEditsFixture only on the authorized disposable Windows machine.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native saved-edit recovery requires Windows; no fixture was launched.' }
$test = 'agent_windows::windows_profiles::windows_headless_edits_native_test::ordinary_403_recovery_requires_current_scope_and_exact_local_file'
$executable = Assert-OrdinaryPath $AgentTestExecutable $false
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Test executable checksum mismatch; nothing was launched.' }
$parent = Assert-OrdinaryPath $OutputParent $true
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Native recovery requires a fixed local NTFS evidence directory.' }
$directory = Join-Path $parent ('raiun-headless-edits-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-edits-native-v1`n")
$receipt = [ordered]@{
    fixture='headless-edits-native-v1'; test=$test; test_executable_sha256=$ExpectedSha256.ToLowerInvariant();
    native_opt_in=$true; evidence=$directory; filesystem=$drive.DriveFormat; timeout_seconds=$TimeoutSeconds;
    started_utc=[DateTime]::UtcNow.ToString('o'); powershell=$PSVersionTable.PSVersion.ToString();
    startup_changed=$false; real_accounts_used=$false; forced_cleanup=$false; all_files_retained=$true;
    registration_cleanup='not attempted; fixture records normal unmount/stop; root, registration and private state retained'
}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_EDITS_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_EDITS_FIXTURE_CHILD=$null
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
} catch {
    $receipt['launch_failed']=$true
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw
} finally {
    foreach ($name in $previous.Keys) {
        $saved = $previous[$name]
        if ($saved.present) { Set-FixtureProcessEnvironment $name $saved.value }
        else { Set-FixtureProcessEnvironment $name $null }
    }
}
$receipt['supervisor_pid']=$process.Id
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
Write-Output "Native synthetic saved-edit fixture PID $($process.Id); retained evidence: $directory"
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $receipt['timeout']=$true
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Fixture remains running after timeout, PID $($process.Id). No process was killed and no root/state was deleted. Retain $directory and child process receipts for normal-disconnect investigation."
}
$process.Refresh()
$receipt['supervisor_exit_code']=$process.ExitCode
$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Native recovery fixture failed. Root, registration, edited bytes, DPAPI state and process logs remain at $directory. No forced cleanup was attempted." }
$resultsPath = Join-Path $directory 'RESULTS.json'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw 'No exact result receipt; do not claim native saved-edit recovery acceptance.' }
Assert-RecoveryResults (Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json)
$receipt['acceptance_passed']=$true
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
Write-Output 'Synthetic ordinary Space 403 retention, stale-scope refusal before remote I/O, wrong-path retention and exact-path verified native/journal completion passed.'
Write-Output 'One refused PUT and one successful recovery PUT were observed. All files, registration and private state remain retained.'
Write-Output 'This does not establish daemon-restart/different-record-generation completion, automatic replay, live server, installed CLI transport, startup or busy-unmount acceptance.'
Write-Output "Evidence: $directory"
