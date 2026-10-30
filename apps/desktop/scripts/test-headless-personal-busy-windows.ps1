# Explicit synthetic Personal save/open-writer acceptance on the authorized disposable Windows PC.
# No install, real account, startup change, forced stop, unregister or deletion.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativePersonalBusyFixture,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(120,1800)][int]$TimeoutSeconds = 900
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
function Assert-PersonalBusyResults($Results) {
    if ($Results.fixture -cne 'headless-personal-busy-native-v1' -or $Results.passed -ne $true -or $Results.forced_cleanup -ne $false -or $Results.registration_retained -ne $true -or $Results.cases.Count -ne 2) {
        throw 'Missing complete Personal/open-writer native acceptance receipts.'
    }
    $names = @($Results.cases | ForEach-Object { $_.scenario } | Sort-Object)
    if (($names -join ',') -cne 'busy,success') { throw 'Unexpected or duplicated acceptance case.' }
    foreach ($case in $Results.cases) {
        if ($case.passed -ne $true -or $case.global_mutation_attempts -ne $case.remote.put_attempt_count) { throw 'Native case failed or unexpected remote mutation occurred.' }
        $phases = @($case.first)
        if ($case.scenario -ceq 'busy') { $phases += $case.restart }
        foreach ($phase in $phases) {
            if ($phase.passed -ne $true -or $phase.normal_unmount -ne $true -or $phase.normal_stop -ne $true -or $phase.edited_bytes_and_registration_retained -ne $true -or $phase.forced_cleanup -ne $false -or $phase.detail.expected_bytes -ne $true -or $phase.detail.exact_root_identity -ne $true -or $phase.detail.folder_generation -ne 0) { throw 'Missing exact bytes/root identity, normal lifecycle or disabled-sync evidence.' }
        }
        if ($case.scenario -ceq 'success') {
            if ($case.first.detail.native_in_sync -ne $true -or $case.remote.put_attempt_count -ne 1 -or $case.remote.put_count -ne 1 -or $case.remote.verified_readback_count -lt 2) { throw 'Personal save lacks exact conditional PUT/readback/native completion evidence.' }
        } else {
            if ($case.first.detail.native_in_sync -ne $false -or $case.restart.detail.native_in_sync -ne $false -or $case.restart.detail.independent_dpapi_restore -ne $true -or $case.remote.put_count -ne 0 -or $case.remote.put_attempt_count -ne $case.remote.forbidden_put_count) { throw 'Dirty bytes were not retained across remount/restart or remote data changed.' }
            if (@('retained_disconnect_while_open','refused_while_open','waited_until_writer_release') -cnotcontains $case.first.detail.unmount_while_open) { throw 'Missing observed open-writer unmount outcome.' }
        }
    }
}
if (-not $RunNativePersonalBusyFixture) { throw 'This test registers two temporary Cloud Files roots, saves a synthetic Personal file and tests retained dirty bytes across open-writer unmount/remount/restart. Pass -RunNativePersonalBusyFixture only on the authorized disposable Windows machine.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Personal save/open-writer acceptance requires Windows; no fixture was launched.' }
$test = 'agent_windows::windows_profiles::windows_headless_busy_test::personal_save_and_open_writer_retained_disconnect'
$executable = Assert-OrdinaryPath $AgentTestExecutable $false
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Test executable checksum mismatch; nothing was launched.' }
$parent = Assert-OrdinaryPath $OutputParent $true
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Native recovery requires a fixed local NTFS evidence directory.' }
$directory = Join-Path $parent ('raiun-headless-personal-busy-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-personal-busy-native-v1`n")
$receipt = [ordered]@{
    fixture='headless-personal-busy-native-v1'; test=$test; test_executable_sha256=$ExpectedSha256.ToLowerInvariant();
    native_opt_in=$true; evidence=$directory; filesystem=$drive.DriveFormat; timeout_seconds=$TimeoutSeconds;
    started_utc=[DateTime]::UtcNow.ToString('o'); powershell=$PSVersionTable.PSVersion.ToString();
    startup_changed=$false; real_accounts_used=$false; forced_cleanup=$false; all_files_retained=$true;
    registration_cleanup='not attempted; fixture records normal unmount/stop; root, registration and private state retained'
}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_BUSY_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_BUSY_FIXTURE_CHILD=$null
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
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw 'No exact result receipt; do not claim native Personal save/open-writer acceptance.' }
Assert-PersonalBusyResults (Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json)
$receipt['acceptance_passed']=$true
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
Write-Output 'Synthetic Personal save and open-writer retained-disconnect/remount/independent DPAPI restart acceptance passed.'
Write-Output 'Personal save applied once; the busy case applied no remote write. All files, registrations, private state and observed unmount outcomes remain retained.'
Write-Output 'This does not establish in-flight PUT/callback drain, automatic replay, all open-file sharing modes, live servers, startup or installed CLI transport.'
Write-Output "Evidence: $directory"
