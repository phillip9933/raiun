# Explicit installed-production CLI acceptance, using only a synthetic loopback account.
# Registers one temporary native Cloud Files root, then normal unmount/stop.
# -RunLogonStartup additionally registers, manually starts and normally removes
# only its exactly bound same-user InteractiveToken task; no password or boot task.
# All installed files, roots, provider registrations, state and evidence remain.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RunInstalledCliNativeReadFixture,
    # Registers/runs/removes only the exact same-user InteractiveToken test task.
    [switch]$RunLogonStartup,
    [string]$OutputParent = $env:TEMP,
    [ValidateRange(120,1800)][int]$TimeoutSeconds = 600
)
$ErrorActionPreference = 'Stop'
if (-not $RunInstalledCliNativeReadFixture) { throw 'This test installs into a fresh prefix and registers a temporary Cloud Files root. Pass -RunInstalledCliNativeReadFixture only on the authorized disposable Windows computer.' }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Use PowerShell 7 for ArgumentList and exact child environment removal.' }
function Assert-OrdinaryPath([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ([bool]$item.PSIsContainer -ne $Directory) { throw 'Unexpected fixture path type.' }
    # Inspect every existing ancestor; never traverse a reparse point into an
    # unrelated directory while installing/extracting/creating a native root.
    $cursor = $item
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Fixture paths and ancestors must not be reparse points.' }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory } else { $cursor = $cursor.Parent }
    }
    return $item.FullName
}
function New-FixtureProcessInfo([string]$Executable, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    foreach ($name in @('RAIUN_HEADLESS_CONTEXT','RAIUN_HEADLESS_CONFIG','RAIUN_STATE_DIR','RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD','RAIUN_HEADLESS_NATIVE_FIXTURE_DIR','RAIUN_HEADLESS_CLI_FIXTURE_DIR','RAIUN_HEADLESS_CLI_INSTALL_DIR','RAIUN_HEADLESS_CLI_LOGON_STARTUP')) {
        # Assigning $null retains empty keys on PowerShell 7.6. Remove is required.
        $info.Environment.Remove($name) | Out-Null
    }
    return $info
}
$archive = Assert-OrdinaryPath $PackageZip $false
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Package checksum mismatch; nothing was extracted or launched.' }
$parent = Assert-OrdinaryPath $OutputParent $true
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($parent))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'Fixture requires a fixed local NTFS evidence parent.' }
$root = Join-Path $parent ('raiun-installed-cli-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$unpacked = Join-Path $root 'package'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 20000) { throw 'Unexpected archive entry count.' }
    $expandedBytes = [long]0
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\','/')
        $expandedBytes += $entry.Length
        if ($name.StartsWith('/') -or $name.Contains(':') -or @($name.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) { throw 'Unsafe archive entry path.' }
        if ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { throw 'Archive symbolic links are refused.' }
        if ($expandedBytes -gt 2147483648) { throw 'Archive exceeds fixture extraction bound.' }
    }
} finally { $zip.Dispose() }
[IO.Compression.ZipFile]::ExtractToDirectory($archive, $unpacked)
$bundles = @(Get-ChildItem -LiteralPath $unpacked -Directory)
if ($bundles.Count -ne 1) { throw 'Package must contain one bundle directory.' }
$bundle = Assert-OrdinaryPath $bundles[0].FullName $true
$manifestPath = Join-Path $bundle 'manifest.json'
$manifest = Get-Content -LiteralPath (Assert-OrdinaryPath $manifestPath $false) -Raw | ConvertFrom-Json
if ($manifest.format -cne 'raiun-headless-windows-candidate-v1') { throw 'Unexpected candidate manifest format.' }
foreach ($entry in $manifest.files.PSObject.Properties) {
    $name = $entry.Name.Replace('\','/')
    if ($name.StartsWith('/') -or $name.Contains(':') -or @($name.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0 -or $entry.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid candidate manifest path/hash.' }
    $path = Assert-OrdinaryPath (Join-Path $bundle $name) $false
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.Value) { throw 'Candidate manifest checksum mismatch.' }
}
foreach ($required in @('raiun.exe','raiun-agent.exe','install.ps1','tests/agent-tests.exe')) {
    if ($manifest.files.PSObject.Properties.Name -cnotcontains $required) { throw 'Candidate is missing a required verified fixture component.' }
}
$install = Join-Path $root 'installed'
$installerInfo = New-FixtureProcessInfo (Get-Process -Id $PID).Path @('-NoProfile','-NonInteractive','-File',(Join-Path $bundle 'install.ps1'),'-Destination',$install)
$installer = [Diagnostics.Process]::Start($installerInfo)
$installer.StandardInput.Close()
$installOut = $installer.StandardOutput.ReadToEndAsync()
$installErr = $installer.StandardError.ReadToEndAsync()
if (-not $installer.WaitForExit(30000)) { throw "Installer is still running, PID $($installer.Id); no process killed. Retain $root." }
[IO.File]::WriteAllText((Join-Path $root 'install.stdout.log'), $installOut.GetAwaiter().GetResult())
[IO.File]::WriteAllText((Join-Path $root 'install.stderr.log'), $installErr.GetAwaiter().GetResult())
if ($installer.ExitCode -ne 0) { throw "Fresh-prefix install failed; retain $root." }
foreach ($name in @('raiun.exe','raiun-agent.exe')) {
    $path = Assert-OrdinaryPath (Join-Path $install $name) $false
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $manifest.files.$name) { throw 'Installed production binary hash mismatch.' }
}
$directory = Join-Path $root 'evidence'
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $directory 'OWNER.txt'), "raiun-headless-installed-cli-v1`n")
$test = 'agent_windows::windows_profiles::windows_headless_cli_test::installed_cli_personal_spaces_and_remembered_restart'
$diagnostic = Join-Path $bundle 'tests/agent-tests.exe'
$receipt = [ordered]@{fixture='installed-headless-cli-v1';package_sha256=$ExpectedSha256.ToLowerInvariant();
    diagnostic_sha256=$manifest.files.'tests/agent-tests.exe';cli_sha256=$manifest.files.'raiun.exe';agent_sha256=$manifest.files.'raiun-agent.exe';
    test=$test;fresh_install=$install;evidence=$directory;native_opt_in=$true;filesystem=$drive.DriveFormat;
    started_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();
    logon_startup_opt_in=[bool]$RunLogonStartup;startup_requested=[bool]$RunLogonStartup;startup_change_possible=[bool]$RunLogonStartup;
    startup_changed=if($RunLogonStartup){$null}else{$false};real_accounts_used=$false;forced_cleanup=$false;all_files_retained=$true}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
$info = New-FixtureProcessInfo $diagnostic @('--ignored','--exact',$test,'--nocapture','--test-threads=1')
$info.Environment['RAIUN_HEADLESS_CLI_FIXTURE_DIR'] = $directory
$info.Environment['RAIUN_HEADLESS_CLI_INSTALL_DIR'] = $install
if ($RunLogonStartup) { $info.Environment['RAIUN_HEADLESS_CLI_LOGON_STARTUP'] = '1' }
$process = [Diagnostics.Process]::Start($info)
$process.StandardInput.Close()
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
Write-Output "Installed CLI fixture PID $($process.Id); retained evidence: $directory"
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $receipt['timeout']=$true;$receipt['supervisor_pid']=$process.Id
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    throw "Fixture remains running, PID $($process.Id). No process was killed; retain $root for safe CLI unmount/stop investigation."
}
[IO.File]::WriteAllText((Join-Path $directory 'supervisor.stdout.log'), $stdout.GetAwaiter().GetResult())
[IO.File]::WriteAllText((Join-Path $directory 'supervisor.stderr.log'), $stderr.GetAwaiter().GetResult())
$receipt['supervisor_exit_code']=$process.ExitCode;$receipt['finished_utc']=[DateTime]::UtcNow.ToString('o')
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
if ($process.ExitCode -ne 0) { throw "Installed CLI fixture failed; retain install/root/state/registrations/logs and any exactly bound startup task at $root. No forced cleanup was performed." }
$results = Get-Content -LiteralPath (Join-Path $directory 'RESULTS.json') -Raw | ConvertFrom-Json
if ($results.fixture -cne 'installed-headless-cli-v1' -or -not $results.passed -or $results.phases.Count -ne 2 -or @($results.phases | Where-Object { -not $_.passed }).Count -ne 0 -or $results.mutation_attempt_count -ne 0 -or $results.personal_get_count -le 0 -or $results.space_get_count -le 0) { throw 'Exact fixture receipts do not establish complete CLI/read/restart acceptance.' }
if ($results.logon_startup.requested -ne [bool]$RunLogonStartup) { throw 'Logon startup opt-in does not match the exact test receipt.' }
if ($RunLogonStartup) {
    $startup = Get-Content -LiteralPath (Join-Path $directory 'LOGON-STARTUP.json') -Raw | ConvertFrom-Json
    if (-not $startup.requested -or -not $startup.attempted -or -not $startup.passed -or $startup.rounds.Count -ne 2 -or @($startup.rounds | Where-Object { -not $_.passed -or -not $_.task_removed }).Count -ne 0) { throw 'Exact logon task runtime/normal removal acceptance is incomplete; retain task/state receipts.' }
    $receipt['startup_changed']=$true
    $receipt['logon_task_removed']=$true
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'runner.json') -Encoding UTF8
    Write-Output 'Optional same-user InteractiveToken task registration, manual start, DPAPI automount/reads and normal exact-task removal passed twice. No owner password or boot trigger was used.'
}
Write-Output 'Installed production CLI, named pipes, stdin app-token completion, Personal+Spaces ordinary reads, graceful unmount/stop and remembered restart passed on this machine.'
if (-not $RunLogonStartup) { Write-Output 'Startup tasks were not enabled; optional logon-task acceptance was not requested.' }
Write-Output 'No writes, real server, actual logon-trigger delivery, boot Session 0, Server Core or GUI coexistence acceptance is implied.'
Write-Output "All files and disconnected native registration retained: $root"
