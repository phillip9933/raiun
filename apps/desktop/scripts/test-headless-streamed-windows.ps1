# Explicit synthetic streamed existing-file acceptance on the authorized disposable PC.
# No installs, real accounts, startup changes, forced stops, unregister or deletion.
param(
    [Parameter(Mandatory=$true)][string]$AgentTestExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunNativeStreamedFixture,
    [ValidateSet('personal-success','space-success','personal-forbidden','space-forbidden','personal-paced','personal-small-paced','personal-paced-expired')][string]$Case,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(60,1800)][int]$TimeoutSeconds = 900
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
if (-not $RunNativeStreamedFixture) { throw 'This test registers temporary Cloud Files roots and edits 2 MiB+7-byte or 17 MiB+7-byte synthetic files. Pass -RunNativeStreamedFixture only on the explicitly authorized disposable Windows machine.' }
$test = 'agent_windows::windows_profiles::windows_headless_streamed_test::synthetic_headless_streamed_existing_file_save'
$executable = (Get-Item -LiteralPath $AgentTestExecutable).FullName
if ((Get-Item -LiteralPath $executable).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The test executable must be an ordinary hash-verified file.' }
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Test executable checksum mismatch; nothing was launched.' }
$parent = (Get-Item -LiteralPath $OutputParent).FullName
if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose an ordinary local evidence parent directory.' }
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Native write fixture needs a fixed local NTFS evidence directory.' }
$directory = Join-Path $parent ('raiun-headless-streamed-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-native-streamed-v1`n")
if (-not [string]::IsNullOrEmpty($Case)) { $Case = $Case.ToLowerInvariant() }
$expectedCases = if ([string]::IsNullOrEmpty($Case)) { @('personal-success','space-success','personal-forbidden','space-forbidden') } else { @($Case) }
$receipt = [ordered]@{ fixture='headless-native-streamed-v1'; test=$test; test_executable_sha256=$ExpectedSha256.ToLowerInvariant();
    native_opt_in=$true; requested_cases=@($expectedCases); evidence=$directory; started_utc=[DateTime]::UtcNow.ToString('o');
    powershell=$PSVersionTable.PSVersion.ToString(); startup_changed=$false; real_accounts_used=$false;
    registration_cleanup='not attempted; roots/edits/state retained; disconnect status is recorded by the fixture' }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$changes = @{
    RAIUN_HEADLESS_STREAMED_FIXTURE_DIR=$directory
    RAIUN_HEADLESS_STREAMED_FIXTURE_CHILD=$null
    RAIUN_HEADLESS_STREAMED_FIXTURE_CASE=$(if ([string]::IsNullOrEmpty($Case)) { $null } else { $Case })
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
Write-Output "Native synthetic streamed fixture PID $($process.Id); evidence: $directory"
$receipt['supervisor_pid']=$process.Id
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $receipt['timeout']=$true; $receipt['supervisor_pid']=$process.Id
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Fixture remains running after timeout. No process was killed or root/state deleted. Preserve PID $($process.Id) and evidence at $directory for normal-disconnect investigation."
}
$process.Refresh()
$receipt['supervisor_exit_code']=$process.ExitCode
$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Native streamed fixture failed. All roots, registrations, edited bytes, DPAPI state and logs remain at $directory. No forced cleanup was attempted." }
$resultsPath = Join-Path $directory 'RESULTS.json'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw 'No exact result receipt; do not claim native write acceptance.' }
$results = Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json
if (-not $results.passed -or $results.fixture -cne 'headless-native-streamed-v1' -or $results.cases.Count -ne $expectedCases.Count -or $results.forced_cleanup -ne $false -or $results.folder_sync -ne $false -or -not $results.registrations_and_state_retained) { throw 'Receipts do not establish the exact requested native streamed cases.' }
$names = @($results.cases | ForEach-Object { $_.case } | Sort-Object)
if (($names -join ',') -cne ((@($expectedCases | Sort-Object)) -join ',')) { throw 'Unexpected or duplicated case receipt.' }
$reportedRequest = @($results.requested_cases | Sort-Object)
if (($reportedRequest -join ',') -cne (($expectedCases | Sort-Object) -join ',')) { throw 'The fixture request scope differs from the runner.' }
if (($expectedCases.Count -eq 4) -ne $results.full_matrix_passed) { throw 'Focused acceptance must not be labeled full matrix acceptance.' }
foreach ($caseResult in $results.cases) {
    $expectedLength = if ($caseResult.case -ceq 'personal-small-paced') { 2097159 } else { 17825799 }
    $expiredCase = $caseResult.case -ceq 'personal-paced-expired'
    $pacedCase = $caseResult.case -in @('personal-paced','personal-small-paced','personal-paced-expired')
    if (-not $caseResult.passed -or $caseResult.global_mutations -ne 1 -or $caseResult.remote.bytes -ne $expectedLength -or $caseResult.remote.put_attempts -ne 1) { throw 'A case lacks exact file mutation evidence.' }
    $caseDirectory = Join-Path $directory $caseResult.case
    $saved = $null
    if ($pacedCase) {
        $expectedRate = if ($caseResult.case -ceq 'personal-small-paced' -or $expiredCase) { 65536 } else { 524288 }
        if ($caseResult.pacing.bytes_per_second -ne $expectedRate -or $caseResult.pacing.elapsed_millis -le 30000) { throw 'Paced case lacks the exact rate and an observation lasting more than 30 seconds.' }
        if ($expiredCase) {
            if ($caseResult.pacing.finished -ne $false -or $caseResult.pacing.sent -le 0 -or $caseResult.pacing.sent -ge $expectedLength) { throw 'Expiry case requires an interrupted partial readback.' }
        } elseif (-not $caseResult.pacing.finished -or $caseResult.pacing.sent -ne $expectedLength) { throw 'Paced success requires the complete conditioned response.' }
    }
    foreach ($role in @('save','restart')) {
        $rolePath = Join-Path $caseDirectory ($role + '.RESULTS.json')
        if (-not (Test-Path -LiteralPath $rolePath -PathType Leaf)) { throw 'A runtime receipt is absent.' }
        $runtime = Get-Content -LiteralPath $rolePath -Raw | ConvertFrom-Json
        if (-not $runtime.passed -or -not $runtime.normal_unmount_stop -or -not $runtime.edited_bytes_registration_retained -or $runtime.forced_cleanup -ne $false -or $runtime.detail.bytes -ne $expectedLength) { throw 'A runtime lacks safe lifecycle, retained bytes, or exact length evidence.' }
        $expectedTimeout = if ($expiredCase) { 60 } else { 120 }
        if ($pacedCase -and $runtime.detail.configured_job_timeout_seconds -ne $expectedTimeout) { throw 'Paced runtime did not retain its configured transfer allowance.' }
        if ($expiredCase -and $role -ceq 'save' -and $runtime.runtime_elapsed_millis -lt 60000) { throw 'Expiry was reported before its configured allowance elapsed.' }
        $refused = $caseResult.case.EndsWith('-forbidden') -or $expiredCase
        if ($runtime.detail.pending -ne $refused -or $runtime.detail.durable_v2_ack -ne (-not $refused) -or $runtime.detail.native_in_sync -ne (-not $refused)) { throw 'Native state and durable v2 recovery evidence disagree.' }
        if ($role -ceq 'save') { $saved = $runtime.detail }
        elseif ($runtime.detail.record_id -cne $saved.record_id -or $runtime.detail.generation -ne $saved.generation -or $runtime.detail.commitment -cne $saved.commitment -or $runtime.detail.sha256 -cne $saved.sha256) { throw 'Restart changed the retained recovery identity, generation, commitment or content.' }
    }
}
Write-Output ('Synthetic requested file cases passed: ' + ($names -join ', '))
Write-Output 'Every registration, edited file and protected v2 journal remains retained. No forced cleanup occurred.'
Write-Output 'This does not establish production large-file activation, namespace CRUD/replacement, real-server login/I/O, true boot, GUI parity, or sync acceptance.'
Write-Output "Evidence: $directory"
