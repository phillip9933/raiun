param(
    [string]$BinDir = $PSScriptRoot,
    [string]$OutputDir = (Join-Path $PSScriptRoot ('test-results-' + [Guid]::NewGuid().ToString('N')))
)
# Synthetic checks only, including loopback app-token/DPAPI restart fixtures.
# Never uses a real account or registers/mounts a root; no startup activation.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$BinDir = (Resolve-Path -LiteralPath $BinDir).Path
if (Test-Path -LiteralPath $OutputDir) { throw 'Choose a new evidence directory.' }
New-Item -ItemType Directory -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$cli = Join-Path $BinDir 'raiun.exe'
$agent = Join-Path $BinDir 'raiun-agent.exe'
$prefix = 'RaiunHeadless-Acceptance-' + [Guid]::NewGuid().ToString('N')
$stateA = Join-Path $env:LOCALAPPDATA ($prefix + '-A')
$stateB = Join-Path $env:LOCALAPPDATA ($prefix + '-B')
$services = [Collections.Generic.List[Diagnostics.Process]]::new()
$checks = [Collections.Generic.List[string]]::new()
function Start-TaskProcess([string]$Executable, [string[]]$Arguments, [string]$State) {
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in $Arguments) { $info.ArgumentList.Add($arg) }
    $info.Environment['RAIUN_HEADLESS_CONTEXT'] = '1'
    $info.Environment['RAIUN_STATE_DIR'] = $State
    $info.Environment.Remove('RAIUN_HEADLESS_CONFIG') | Out-Null
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start task process.' }
    return $process
}
function Invoke-Task([string]$Executable, [string[]]$Arguments, [string]$State, [int]$Timeout = 20000) {
    $p = Start-TaskProcess $Executable $Arguments $State
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($Timeout)) {
        $p.Kill($true)
        $p.WaitForExit()
        throw 'Task command timed out; inspect agent state before retrying.'
    }
    return @{ code=$p.ExitCode; stdout=$stdout.GetAwaiter().GetResult(); stderr=$stderr.GetAwaiter().GetResult() }
}
function Drive([string]$State, [string[]]$Arguments, [bool]$Success = $true) {
    $result = Invoke-Task $cli (@('drive','--state-dir',$State,'--json') + $Arguments) $State
    if (($result.code -eq 0) -ne $Success) { throw "Unexpected command result: $($result.stderr)" }
    if ($Success) { return ($result.stdout | ConvertFrom-Json) }
    return $result
}
$success = $false
try {
    $manifest = Get-Content -LiteralPath (Join-Path $BinDir 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files.PSObject.Properties) {
        if ($entry.Name.Contains('..') -or [IO.Path]::IsPathFullyQualified($entry.Name)) { throw 'Invalid manifest path.' }
        $path = Join-Path $BinDir $entry.Name
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.Value) { throw 'Candidate file hash mismatch.' }
    }
    $checks.Add('candidate-checksums')
    # Test executables inherit no headless context in their parent process;
    # their explicitly named subprocess fixtures establish isolated contexts.
    foreach ($test in @(
        @('tests/control-tests.exe','headless'),
        @('tests/control-tests.exe','startup::'),
        @('tests/control-tests.exe','recovery_protection_preserves_admitted_base_and_profile_directory_policy'),
        @('tests/provider-tests.exe','registration_domain'),
        @('tests/provider-tests.exe','headless_current_user_recovery'),
        @('tests/agent-tests.exe','windows_headless')
    )) {
        $path = Join-Path $BinDir $test[0]
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing native test binary: $($test[0])" }
        $info = [Diagnostics.ProcessStartInfo]::new($path)
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.Environment.Remove('RAIUN_HEADLESS_CONTEXT') | Out-Null
        $info.Environment.Remove('RAIUN_STATE_DIR') | Out-Null
        $info.Environment.Remove('RAIUN_HEADLESS_CONFIG') | Out-Null
        foreach ($arg in @($test[1],'--nocapture','--test-threads=1')) { $info.ArgumentList.Add($arg) }
        $p = [Diagnostics.Process]::Start($info)
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(120000)) { $p.Kill($true); throw 'Native fixture timeout.' }
        $text = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        $logName = ([IO.Path]::GetFileNameWithoutExtension($test[0]) + '-' + ($test[1] -replace '[^A-Za-z0-9_.-]', '_') + '.log')
        Set-Content -LiteralPath (Join-Path $OutputDir $logName) -Value $text
        if ($p.ExitCode -ne 0 -or $text -notmatch 'test result: ok\.' -or $text -match '0 passed;') { throw "Native fixture failed or executed no cases: $logName" }
        $checks.Add($logName)
    }
    foreach ($state in @($stateA,$stateB)) {
        $p = Start-TaskProcess $cli @('drive','--state-dir',$state,'serve') $state
        $services.Add($p)
        Start-Sleep -Milliseconds 700
        if ($p.HasExited) { throw "Isolated agent exited early: $($p.StandardError.ReadToEnd())" }
        $status = Drive $state @('status')
        if ($status.runtime_mode -ne 'mount_only' -or $status.credential_storage -ne 'memory_only' -or $status.folder_sync_enabled -ne $false -or $status.connected -ne $false -or $status.mounted -ne $false) { throw 'Wrong initial headless policy.' }
    }
    $checks.Add('two-independent-headless-agents')
    $before = Drive $stateB @('accounts','list')
    $added = Drive $stateA @('accounts','add','--label','Synthetic CLI account')
    $after = Drive $stateB @('accounts','list')
    if (($before | ConvertTo-Json -Depth 20 -Compress) -ne ($after | ConvertTo-Json -Depth 20 -Compress)) { throw 'Account registry crossed state roots.' }
    $checks.Add('account-state-isolation')
    Drive $stateA @('spaces') $false | Out-Null
    Drive $stateA @('mount') $false | Out-Null
    foreach ($action in @('sync_now','pair_add','media_job_run','set_autostart')) {
        $request = @{action=$action;required_mode='mount_only'} | ConvertTo-Json -Compress
        $result = Invoke-Task $agent @('request',$request) $stateA
        if ($result.code -ne 0 -or ($result.stdout | ConvertFrom-Json).ok -ne $false) { throw 'Mount-only operation guard failed.' }
    }
    $wrongMode = Invoke-Task $agent @('request','{"action":"status","required_mode":"desktop"}') $stateA
    if (($wrongMode.stdout | ConvertFrom-Json).ok -ne $false) { throw 'Mode mismatch was accepted.' }
    $checks.Add('no-sync-and-wrong-mode-refusals')
    Drive $stateA @('unmount') | Out-Null
    Drive $stateA @('logout') | Out-Null
    foreach ($state in @($stateA,$stateB)) { Drive $state @('stop') | Out-Null }
    foreach ($p in $services) { if (-not $p.WaitForExit(15000) -or $p.ExitCode -ne 0) { throw 'Safe shutdown failed.' } }
    $checks.Add('logout-and-safe-shutdown')
    $success = $true
} finally {
    foreach ($state in @($stateA,$stateB)) {
        try { Invoke-Task $agent @('request','{"action":"shutdown","required_mode":"mount_only"}') $state 3000 | Out-Null } catch { }
    }
    foreach ($p in $services) {
        if (-not $p.HasExited) { $p.Kill($true); $p.WaitForExit(); $checks.Add('forced-task-only-cleanup') }
    }
    @{success=$success;checks=@($checks);stateRoots=@($stateA,$stateB);noSignIn=$true;noMount=$true;noInstalledAppChanges=$true;target=$manifest.target;source=$manifest.source} |
        ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $OutputDir 'RESULTS.json')
}
Write-Output "Disconnected Windows CLI checks passed. Evidence: $OutputDir"
