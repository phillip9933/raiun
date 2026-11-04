# Hash-verified, explicit automatic OS-mkdir diagnostic on an authorized disposable PC.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativeDirectoryFixture,
    [ValidateSet('personal-success','space-success','personal-nested','personal-bootstrap','personal-losthint','personal-lostresponse')][string]$Case = 'personal-success',
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(60,1800)][int]$TimeoutSeconds = 900
)
$ErrorActionPreference = 'Stop'
if (-not $RunNativeDirectoryFixture) { throw 'This diagnostic registers a fresh Cloud Files root and automatically publishes synthetic OS mkdir operations to a loopback server. Explicitly authorize the disposable Windows machine and pass -RunNativeDirectoryFixture.' }
$test = 'agent_windows::windows_profiles::windows_headless_directory_test::native::synthetic_headless_automatic_directory_create'
$executable = (Get-Item -LiteralPath $AgentTestExecutable).FullName
if ((Get-Item -LiteralPath $executable).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Use an ordinary hash-verified test executable.' }
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Executable checksum mismatch; nothing launched.' }
$parent = (Get-Item -LiteralPath $OutputParent).FullName
if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose an ordinary local evidence parent.' }
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'The fixture requires fixed local NTFS storage.' }
$directory = Join-Path $parent ('raiun-headless-directory-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-automatic-directory-v1`n")
$Case = $Case.ToLowerInvariant()
$receipt = [ordered]@{ fixture='headless-automatic-directory-v1'; test=$test; requested_cases=@($Case); evidence=$directory;
    test_executable_sha256=$ExpectedSha256.ToLowerInvariant(); started_utc=[DateTime]::UtcNow.ToString('o');
    production_enabled=$false; real_accounts_used=$false; forced_cleanup=$false; registration_cleanup='not attempted; all roots/state/data retained' }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_DIRECTORY_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_DIRECTORY_FIXTURE_CHILD=$null
    RAIUN_HEADLESS_DIRECTORY_FIXTURE_CASE=$Case
    RAIUN_HEADLESS_CONTEXT=$null
    RAIUN_HEADLESS_CONFIG=$null
    RAIUN_STATE_DIR=$null
    RAIUN_HEADLESS_STREAMED_FIXTURE_DIR=$null
    RAIUN_HEADLESS_STREAMED_FIXTURE_CHILD=$null
    RAIUN_HEADLESS_STREAMED_FIXTURE_CASE=$null
}
function Set-FixtureEnvironment([string]$Name,[AllowNull()][object]$Value) {
    if ($null -eq $Value) { if (Test-Path -LiteralPath ('Env:'+$Name)) { Remove-Item -LiteralPath ('Env:'+$Name) -ErrorAction Stop } }
    else { [Environment]::SetEnvironmentVariable($Name,[string]$Value,'Process') }
}
$previous = @{}
try {
    foreach ($name in $changes.Keys) {
        $previous[$name] = @{ present=[Environment]::GetEnvironmentVariables('Process').Contains($name); value=[Environment]::GetEnvironmentVariable($name,'Process') }
        Set-FixtureEnvironment $name $changes[$name]
    }
    $process = Start-Process -FilePath $executable -ArgumentList @('--ignored','--exact',$test,'--nocapture','--test-threads=1') -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $directory 'supervisor.stdout.log') -RedirectStandardError (Join-Path $directory 'supervisor.stderr.log')
} finally {
    foreach ($name in $previous.Keys) { if ($previous[$name].present) { Set-FixtureEnvironment $name $previous[$name].value } else { Set-FixtureEnvironment $name $null } }
}
$receipt['supervisor_pid']=$process.Id
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
Write-Output "Automatic mkdir fixture PID $($process.Id); evidence: $directory"
if (-not $process.WaitForExit($TimeoutSeconds*1000)) {
    $receipt['timeout']=$true
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Fixture remains running. No process killed or root/state removed. Preserve PID $($process.Id) and all evidence at $directory; server ownership remains inside the supervisor until exact children exit."
}
$process.Refresh()
$receipt['supervisor_exit_code']=$process.ExitCode
$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Native automatic mkdir failed; all state/roots/data retained at $directory. Stop; do not run the next selector." }
$result = Get-Content -LiteralPath (Join-Path $directory 'RESULTS.json') -Raw | ConvertFrom-Json
if ($result.fixture -cne 'headless-automatic-directory-v1' -or -not $result.passed -or -not $result.native_execution -or -not $result.automatic_os_discovery -or $result.production_enabled -ne $false -or $result.live_server -ne $false -or $result.folder_sync -ne $false -or $result.forced_cleanup -ne $false -or -not $result.registrations_and_state_retained -or $result.cases.Count -ne 1 -or $result.requested_cases.Count -ne 1 -or $result.requested_cases[0] -cne $Case) { throw 'Exact scoped automatic native acceptance receipt missing.' }
$caseResult=$result.cases[0]
$expected = if ($Case -ceq 'personal-nested') { 2 } else { 1 }
if ($caseResult.case -cne $Case -or -not $caseResult.passed -or $caseResult.global_mutations -ne $expected -or $caseResult.remote.attempts.Count -ne $expected -or $caseResult.remote.created.Count -ne $expected -or $caseResult.remote.invalid -ne 0) { throw 'Exact create-only mutation evidence failed.' }
$roles = if ($Case -ceq 'personal-lostresponse') { @('save','restart') } else { @('save') }
foreach ($role in $roles) {
    $runtime = Get-Content -LiteralPath (Join-Path (Join-Path $directory $Case) ($role+'.RESULTS.json')) -Raw | ConvertFrom-Json
    if (-not $runtime.passed -or -not $runtime.normal_unmount_stop -or $runtime.forced_cleanup -ne $false -or -not $runtime.registrations_and_state_retained -or $runtime.detail.records.Count -ne $expected) { throw 'Native runtime lifecycle/history evidence incomplete.' }
    foreach ($record in $runtime.detail.records) {
        if ($Case -ceq 'personal-lostresponse') {
            if ($record.local_completed -ne $false -or $record.remote -cne 'Submitted' -or $record.attention -cne 'Some(Uncertain)' -or $record.placeholder_state -ne 0) { throw 'Lost response must remain uncertain/plain and never replay.' }
        } elseif (-not $record.local_completed -or $record.remote -cne 'Verified' -or $record.attention -cne 'None' -or ($record.placeholder_state -band 1) -eq 0 -or ($record.placeholder_state -band 8) -ne 0 -or -not $record.identity_present) { throw 'Directory conversion must be durable with identity and without IN_SYNC.' }
    }
    if ($Case -ceq 'personal-losthint' -and ($runtime.detail.discarded_hints_after_io -lt 1 -or -not $runtime.detail.continuity_lost)) { throw 'Lost-hint selector lacks an actual discarded hint.' }
}
Write-Output "PASS scoped automatic mkdir selector $Case. All roots, registrations, retained child bytes and protected state remain at $directory. No real-server OC9 semantics or other selectors are implied."
