[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BaselineArtifactRoot,
    [Parameter(Mandatory = $true)][string] $FinalArtifactRoot,
    [Parameter(Mandatory = $true)][string] $OutputDirectory
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
$ErrorActionPreference = 'Stop'

# Refuse outside the disposable runner before any file/registry operation or cleanup.
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'phillip9933/raiun') {
    throw 'github_hosted_windows_required'
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'output_directory_already_exists' }

$script:events = [System.Collections.Generic.List[object]]::new()
$script:phase = 'preflight'
$script:failure = $null
$script:agent = $null
$script:agentPath = $null
$script:baseline = $null
$script:final = $null
$script:installRoot = $null
$script:settingsPath = $null
$script:documentPath = $null
$script:canaryPath = $null
$script:retentionPaths = @()
$script:canaryEntropy = $null
$script:canaryPlainHash = $null
$script:baselineInstallExit = $null
$script:busyInstallExit = $null
$script:finalInstallExit = $null
$script:baselineAgentExit = $null
$script:finalAgentExit = $null
$script:baselineFiles = $null
$script:finalFiles = $null
$script:startupAppData = $env:APPDATA
$script:startupLocalAppData = $env:LOCALAPPDATA
$script:sidHash = $null
$script:result = 'failed'

function Add-Event([string] $Name, [string] $Result, [hashtable] $Details = @{}) {
    $item = [ordered]@{ utc = [DateTime]::UtcNow.ToString('o'); phase = $Name; result = $Result }
    foreach ($key in $Details.Keys) { $item[$key] = $Details[$key] }
    $row = [pscustomobject]$item
    $script:events.Add($row)
    if (Test-Path -LiteralPath $OutputDirectory) {
        $line = ConvertTo-Json -InputObject $row -Compress -Depth 6
        [IO.File]::AppendAllText((Join-Path $OutputDirectory 'acceptance.log'), $line + "`n", [Text.UTF8Encoding]::new($false))
    }
}

function Hash-Bytes([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Pin-File([string] $Path) {
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{ length = [long]$file.Length; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Read-Candidate([string] $Root, [string] $SourceCommit) {
    $manifests = @(Get-ChildItem -LiteralPath $Root -Filter '*.manifest.json' -File -Recurse)
    $setups = @(Get-ChildItem -LiteralPath $Root -Filter '*-setup.exe' -File -Recurse)
    $archives = @(Get-ChildItem -LiteralPath $Root -Filter '*.nsis.zip' -File -Recurse)
    if ($manifests.Count -ne 1 -or $setups.Count -ne 1 -or $archives.Count -ne 1) { throw 'artifact_layout_mismatch' }
    $manifest = Get-Content -LiteralPath $manifests[0].FullName -Raw | ConvertFrom-Json
    if ($manifest.format -cne 'raiun-windows-installer-v1' -or $manifest.target -cne 'x86_64-pc-windows-msvc' -or
        $manifest.sourceCommit -cne $SourceCommit -or $manifest.sourceDirty -ne $false -or $manifest.signed -ne $false -or
        $manifest.updaterArtifact.version -cne '0.7.4') { throw 'manifest_source_or_version_mismatch' }
    $setup = Pin-File $setups[0].FullName
    $archive = Pin-File $archives[0].FullName
    $admitted = switch ($SourceCommit) {
        '1c60b4e6d7084ff5c3ba3f96b547d028e4c171cc' { @('23c110a798abf8f4d844f047d29c729216e01bc8018eb15f61291ea5117fad6e', 'bde4244d54643f4af0e14a59637cb162bcf17e730e4b6bbefa0e9dc7d66128aa') }
        '26ccf130b3274d1f3ae9661b62bc19cb7cfd33b4' { @('389ee3fda30501d24c134713881beedbb91a6119d2e0e2b84885dcf876803231', 'bba0ec952d5e1bb1aac08ba5fe03288e931b4620f8fb99a98c0f53d74bd19b29') }
        default { throw 'unadmitted_candidate_source' }
    }
    if ($setup.sha256 -cne $admitted[0] -or $archive.sha256 -cne $admitted[1]) { throw 'unadmitted_candidate_hash' }
    if ($setups[0].Name -cne $manifest.installer.name -or $setup.length -ne [long]$manifest.installer.length -or
        $setup.sha256 -cne [string]$manifest.installer.sha256 -or
        $archive.length -ne [long]$manifest.updaterArtifact.length -or
        $archive.sha256 -cne [string]$manifest.updaterArtifact.sha256) { throw 'artifact_hash_mismatch' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archives[0].FullName)
    try {
        $entries = @($zip.Entries)
        if ($entries.Count -ne 1 -or $entries[0].Name -cne $setups[0].Name -or $entries[0].Length -ne $setup.length) { throw 'updater_archive_layout_mismatch' }
        $stream = $entries[0].Open()
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $innerHash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
        } finally { $stream.Dispose() }
        if ($innerHash -cne $setup.sha256) { throw 'updater_archive_setup_mismatch' }
    } finally { $zip.Dispose() }
    $payloads = @($manifest.payloads)
    $shell = $manifest.applicationShell.bundledExpected
    if ($payloads.Count -ne 2 -or @($payloads | Where-Object name -CEQ 'raiun-agent.exe').Count -ne 1 -or
        @($payloads | Where-Object name -CEQ 'raiun.exe').Count -ne 1 -or $shell.bundleType -cne 'nsis' -or $shell.target -cne 'x64') {
        throw 'manifest_payload_layout_mismatch'
    }
    return [pscustomobject]@{
        sourceCommit = $SourceCommit
        version = [string]$manifest.updaterArtifact.version
        installerPath = $setups[0].FullName
        installerSha256 = $setup.sha256
        manifestSha256 = (Get-FileHash -LiteralPath $manifests[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        archiveSha256 = $archive.sha256
        payloads = $payloads
        shell = $shell
    }
}

function Check-InstalledFiles($Candidate) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $expect = @(@{ name = 'raiun-desktop-shell.exe'; length = $Candidate.shell.length; sha256 = $Candidate.shell.sha256 }) + @($Candidate.payloads)
    foreach ($entry in $expect) {
        $script:phase = 'installed_payload_' + ([string]$entry.name).Replace('.exe', '')
        $path = Join-Path $script:installRoot ([string]$entry.name)
        $pin = Pin-File $path
        if ($pin.length -ne [long]$entry.length -or $pin.sha256 -cne [string]$entry.sha256) { throw 'installed_payload_hash_mismatch' }
        $rows.Add([pscustomobject]@{ name = [string]$entry.name; length = $pin.length; sha256 = $pin.sha256 })
    }
    return ,$rows.ToArray()
}

function Run-Process([string] $Path, [string[]] $Arguments, [int] $TimeoutMs) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Path
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'process_start_failed' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMs)) { throw 'process_wait_timeout' }
    $process.Refresh()
    if ($null -eq $process.ExitCode) { throw 'process_exit_code_missing' }
    $code = [int]$process.ExitCode
    $outBytes = [Text.Encoding]::UTF8.GetByteCount($stdout.GetAwaiter().GetResult())
    $errBytes = [Text.Encoding]::UTF8.GetByteCount($stderr.GetAwaiter().GetResult())
    $process.Dispose()
    return [pscustomobject]@{ exitCode = $code; stdoutBytes = $outBytes; stderrBytes = $errBytes }
}

function Start-Agent([string] $AgentPath) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $AgentPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.ArgumentList.Add('serve')
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'agent_start_failed' }
    $script:agent = $process
    $script:agentPath = $AgentPath
    $script:agentOutTask = $process.StandardOutput.ReadToEndAsync()
    $script:agentErrTask = $process.StandardError.ReadToEndAsync()
}

function Invoke-Control([string] $AgentPath, [System.Collections.IDictionary] $Request) {
    $json = ConvertTo-Json -InputObject $Request -Compress -Depth 8
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $AgentPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.ArgumentList.Add('request')
    $info.ArgumentList.Add($json)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'agent_request_start_failed' }
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) { throw 'agent_request_timeout' }
    $process.Refresh()
    if ($null -eq $process.ExitCode) { throw 'agent_request_exit_code_missing' }
    $exitCode = [int]$process.ExitCode
    $raw = $outTask.GetAwaiter().GetResult()
    $null = $errTask.GetAwaiter().GetResult()
    $process.Dispose()
    if ($exitCode -ne 0) { throw 'agent_request_nonzero_exit' }
    try { return ($raw | ConvertFrom-Json) } catch { throw 'agent_response_invalid_json' }
}

function Stop-Agent {
    if ($null -eq $script:agent) { return $null }
    $reply = Invoke-Control -AgentPath $script:agentPath -Request ([ordered]@{ action = 'shutdown' })
    if ($reply.ok -ne $true -or $reply.data.stopping -ne $true) { throw 'agent_shutdown_rpc_refused' }
    if (-not $script:agent.WaitForExit(20000)) { throw 'agent_shutdown_timeout' }
    $script:agent.Refresh()
    if ($null -eq $script:agent.ExitCode) { throw 'agent_shutdown_exit_code_missing' }
    $code = [int]$script:agent.ExitCode
    if ($code -ne 0) { throw 'agent_shutdown_nonzero_exit' }
    $script:agent.Dispose()
    $script:agent = $null
    $script:agentPath = $null
    return $code
}

function Check-OfflineStatus($Reply, [bool] $RequireFolderSettings = $false) {
    if ($Reply.ok -ne $true) { throw 'agent_status_refused' }
    $data = $Reply.data
    if ($data.connected -ne $false -or $data.offline -ne $false -or $data.mounted -ne $false -or
        $null -ne $data.server -or $null -ne $data.client_id -or $null -ne $data.cloud_root) { throw 'unexpected_account_or_mount_state' }
    $folderSettingsSupported = $false
    $folderSettingsProperty = $data.PSObject.Properties['folder_settings_supported']
    if ($null -ne $folderSettingsProperty) { $folderSettingsSupported = [bool]$folderSettingsProperty.Value }
    if ($RequireFolderSettings -and -not $folderSettingsSupported) { throw 'folder_settings_capability_missing' }
    return [pscustomobject]@{
        connected = [bool]$data.connected
        offline = [bool]$data.offline
        mounted = [bool]$data.mounted
        hasServer = ($null -ne $data.server)
        hasClientId = ($null -ne $data.client_id)
        hasCloudRoot = ($null -ne $data.cloud_root)
        folderSettingsSupported = $folderSettingsSupported
        authGeneration = [long]$data.auth_generation
    }
}

function Check-InstallRegistration {
    $uninstall = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $matches = @()
    if (Test-Path -LiteralPath $uninstall) {
        foreach ($key in @(Get-ChildItem -LiteralPath $uninstall)) {
            $value = Get-ItemProperty -LiteralPath $key.PSPath
            $displayName = $value.PSObject.Properties['DisplayName']
            if ($null -ne $displayName -and [string]$displayName.Value -ceq 'Raiun Desktop') { $matches += $value }
        }
    }
    if ($matches.Count -ne 1 -or [string]$matches[0].DisplayVersion -cne '0.7.4') { throw 'installed_app_registration_mismatch' }
    $location = ([string]$matches[0].InstallLocation).Trim('"').TrimEnd('\')
    if (-not [string]::Equals($location, $script:installRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'install_location_mismatch' }
    return [pscustomobject]@{ entries = $matches.Count; version = [string]$matches[0].DisplayVersion; currentUser = $true }
}

function Check-StartMenuShortcut {
    $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    $folder = Join-Path $programs 'Raiun'
    $expected = Join-Path $script:installRoot 'raiun-desktop-shell.exe'
    $shell = New-Object -ComObject WScript.Shell
    try {
        $count = 0
        if (Test-Path -LiteralPath $folder) {
            foreach ($link in @(Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -File -Recurse)) {
                if ([string]::Equals($shell.CreateShortcut($link.FullName).TargetPath.Trim('"'), $expected, [StringComparison]::OrdinalIgnoreCase)) { $count++ }
            }
        }
    } finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null }
    if ($count -lt 1) { throw 'start_menu_shortcut_missing' }
    return $count
}

function Check-DataRetention {
    foreach ($entry in $script:retentionPaths) {
        $script:phase = 'retention_' + [string]$entry.name
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { throw 'synthetic_data_missing' }
        $pin = Pin-File $entry.path
        if ($pin.sha256 -cne $entry.expected.sha256 -or $pin.length -ne $entry.expected.length) { throw 'synthetic_data_changed' }
    }
    $script:phase = 'retention_dpapi_unprotect'
    $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($script:canaryPath), $script:canaryEntropy,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ((Hash-Bytes $plain) -cne $script:canaryPlainHash) { throw 'dpapi_current_user_decrypt_failed' }
    $files = @($script:retentionPaths | ForEach-Object { [pscustomobject]@{ name = $_.name; length = $_.expected.length; sha256 = $_.expected.sha256 } })
    return [pscustomobject]@{ files = $files; dpapiCurrentUserDecryptSucceeded = $true }
}

$script:baselineStatus = $null
$script:finalStatus = $null
$script:invalidPairRejected = $false
$script:registration = [ordered]@{ baseline = $null; final = $null }
$script:shortcutCounts = [ordered]@{ baseline = $null; final = $null }
$script:retained = $null

try {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:sidHash = Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($sid))
    $script:phase = 'artifact_manifest_validation'
    $script:baseline = Read-Candidate -Root $BaselineArtifactRoot -SourceCommit '1c60b4e6d7084ff5c3ba3f96b547d028e4c171cc'
    $script:final = Read-Candidate -Root $FinalArtifactRoot -SourceCommit '26ccf130b3274d1f3ae9661b62bc19cb7cfd33b4'
    Add-Event 'artifact_manifest_validation' 'passed' @{ baselineInstallerSha256 = $script:baseline.installerSha256; finalInstallerSha256 = $script:final.installerSha256 }

    $testRoot = Join-Path $env:RUNNER_TEMP ('raiun-074-acceptance-' + [guid]::NewGuid().ToString('N'))
    $script:installRoot = Join-Path $testRoot 'install'
    if ($script:installRoot.Contains(' ') -or $script:installRoot.Contains('"')) { throw 'nsis_install_path_contains_spaces' }
    $dataRoot = Join-Path $testRoot 'profile'
    New-Item -ItemType Directory -Path $dataRoot | Out-Null
    $realRoaming = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
    $realLocal = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $env:APPDATA = Join-Path $dataRoot 'Roaming'
    $env:LOCALAPPDATA = Join-Path $dataRoot 'Local'
    New-Item -ItemType Directory -Path $env:APPDATA,$env:LOCALAPPDATA | Out-Null
    $isolatedRoaming = Join-Path $env:APPDATA 'org.raiun.desktop'
    $isolatedLocal = Join-Path $env:LOCALAPPDATA 'Raiun'
    $realRoaming = Join-Path $realRoaming 'org.raiun.desktop'
    $realLocal = Join-Path $realLocal 'Raiun'
    New-Item -ItemType Directory -Path $isolatedRoaming,$isolatedLocal,$realRoaming,$realLocal -Force | Out-Null
    $script:settingsPath = Join-Path $isolatedRoaming 'desktop-updater.json'
    $script:documentPath = Join-Path $isolatedLocal 'synthetic-document.txt'
    $script:canaryPath = Join-Path $isolatedLocal 'dpapi-canary.bin'
    $actualSettingsPath = Join-Path $realRoaming 'desktop-updater.json'
    $actualDocumentPath = Join-Path $realLocal ('acceptance-document-' + [guid]::NewGuid().ToString('N') + '.txt')
    $actualCanaryPath = Join-Path $realLocal ('acceptance-dpapi-' + [guid]::NewGuid().ToString('N') + '.bin')
    if (Test-Path -LiteralPath $actualSettingsPath) { throw 'hosted_runner_profile_not_clean' }
    $settings = [ordered]@{ automatic_checks = $false; channel = 'beta'; dismissed_tag = $null; last_check_unix = $null }
    $settingsJson = ConvertTo-Json -InputObject $settings -Compress
    [IO.File]::WriteAllText($script:settingsPath, $settingsJson, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($actualSettingsPath, $settingsJson, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($script:documentPath, 'Synthetic Raiun acceptance document.', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($actualDocumentPath, 'Synthetic Raiun known-folder document.', [Text.UTF8Encoding]::new($false))
    $script:canaryEntropy = [Text.Encoding]::UTF8.GetBytes('raiun-hosted-installed-package-acceptance-v1')
    $canaryPlain = [Text.Encoding]::UTF8.GetBytes('synthetic-dpapi-' + [guid]::NewGuid().ToString('N'))
    $script:canaryPlainHash = Hash-Bytes $canaryPlain
    $cipher = [Security.Cryptography.ProtectedData]::Protect($canaryPlain, $script:canaryEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes($script:canaryPath, $cipher)
    [IO.File]::WriteAllBytes($actualCanaryPath, $cipher)
    $script:retentionPaths = @(
        @{ name = 'isolated_updater_settings'; path = $script:settingsPath; expected = Pin-File $script:settingsPath },
        @{ name = 'knownfolder_updater_settings'; path = $actualSettingsPath; expected = Pin-File $actualSettingsPath },
        @{ name = 'isolated_document'; path = $script:documentPath; expected = Pin-File $script:documentPath },
        @{ name = 'isolated_dpapi'; path = $script:canaryPath; expected = Pin-File $script:canaryPath },
        @{ name = 'knownfolder_document'; path = $actualDocumentPath; expected = Pin-File $actualDocumentPath },
        @{ name = 'knownfolder_dpapi'; path = $actualCanaryPath; expected = Pin-File $actualCanaryPath }
    )
    Add-Event 'synthetic_profile_seeded' 'passed' @{ protectedFileCount = $script:retentionPaths.Count; dpapiCiphertextSha256 = (Pin-File $script:canaryPath).sha256 }

    $script:phase = 'baseline_install'
    $baselineResult = Run-Process -Path $script:baseline.installerPath -Arguments @('/S', "/D=$script:installRoot") -TimeoutMs 180000
    $script:baselineInstallExit = $baselineResult.exitCode
    if ($script:baselineInstallExit -ne 0) { throw 'baseline_installer_failed' }
    $script:baselineFiles = Check-InstalledFiles $script:baseline
    $script:registration.baseline = Check-InstallRegistration
    $script:shortcutCounts.baseline = Check-StartMenuShortcut
    Add-Event 'baseline_install' 'passed' @{ exitCode = $script:baselineInstallExit; installedPayloadCount = $script:baselineFiles.Count; uninstallEntryCount = $script:registration.baseline.entries; startMenuShortcuts = $script:shortcutCounts.baseline }

    $baselineAgent = Join-Path $script:installRoot 'raiun-agent.exe'
    $script:phase = 'baseline_agent_process_start'
    Start-Agent $baselineAgent
    Add-Event 'baseline_agent_process_start' 'passed'
    $script:phase = 'baseline_agent_status_request'
    $baselineReply = $null
    $until = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $script:agent.Refresh()
        if ($script:agent.HasExited) { throw 'baseline_agent_exited' }
        try { $baselineReply = Invoke-Control $baselineAgent ([ordered]@{ action = 'status' }); break }
        catch { Start-Sleep -Milliseconds 250 }
    } while ([DateTime]::UtcNow -lt $until)
    if ($null -eq $baselineReply) { throw 'baseline_agent_not_ready' }
    $script:phase = 'baseline_agent_status_validation'
    $script:baselineStatus = Check-OfflineStatus $baselineReply
    $script:phase = 'busy_installer_invocation'
    $busy = Run-Process -Path $script:final.installerPath -Arguments @('/S', "/D=$script:installRoot") -TimeoutMs 180000
    $script:busyInstallExit = $busy.exitCode
    $script:phase = 'busy_agent_process_state'
    $script:agent.Refresh()
    if ($script:busyInstallExit -eq 0 -or $script:agent.HasExited) { throw 'busy_guard_did_not_fail_closed' }
    $script:phase = 'busy_payload_retention'
    $afterBusy = Check-InstalledFiles $script:baseline
    $script:phase = 'busy_synthetic_data_retention'
    $busyData = Check-DataRetention
    $script:phase = 'busy_registry_check'
    $script:registration.baseline = Check-InstallRegistration
    $script:phase = 'busy_agent_postattempt_status'
    $script:baselineStatus = Check-OfflineStatus (Invoke-Control $baselineAgent ([ordered]@{ action = 'status' }))
    $script:phase = 'busy_guard_receipt'
    Add-Event 'busy_guard' 'passed' @{ installerExitCode = $script:busyInstallExit; baselineFilesUnchanged = ($afterBusy.Count -eq $script:baselineFiles.Count); syntheticDataUnchanged = $true; dpapiDecryptSucceeded = $busyData.dpapiCurrentUserDecryptSucceeded; registeredAppCount = $script:registration.baseline.entries; agentStillRunning = $true; connected = $script:baselineStatus.connected; mounted = $script:baselineStatus.mounted }

    $script:phase = 'baseline_agent_shutdown'
    $script:baselineAgentExit = Stop-Agent
    if ($script:baselineAgentExit -ne 0) { throw 'baseline_agent_shutdown_failed' }
    Add-Event 'baseline_agent_shutdown' 'passed' @{ exitCode = $script:baselineAgentExit }

    $script:phase = 'final_in_place_upgrade'
    $upgrade = Run-Process -Path $script:final.installerPath -Arguments @('/S', "/D=$script:installRoot") -TimeoutMs 180000
    $script:finalInstallExit = $upgrade.exitCode
    if ($script:finalInstallExit -ne 0) { throw 'final_installer_failed' }
    $script:finalFiles = Check-InstalledFiles $script:final
    $script:registration.final = Check-InstallRegistration
    $script:shortcutCounts.final = Check-StartMenuShortcut
    $script:retained = Check-DataRetention
    Add-Event 'final_in_place_upgrade' 'passed' @{ exitCode = $script:finalInstallExit; installedPayloadCount = $script:finalFiles.Count; uninstallEntryCount = $script:registration.final.entries; startMenuShortcuts = $script:shortcutCounts.final; dpapiDecryptSucceeded = $true; settingsRetained = $true; syntheticDocumentRetained = $true }

    $finalAgent = Join-Path $script:installRoot 'raiun-agent.exe'
    $script:phase = 'final_agent_process_start'
    Start-Agent $finalAgent
    Add-Event 'final_agent_process_start' 'passed'
    $script:phase = 'final_agent_status_request'
    $until = [DateTime]::UtcNow.AddSeconds(20)
    $script:agent.Refresh()
    $finalReply = $null
    do {
        if ($script:agent.HasExited) { throw 'final_agent_exited' }
        try { $finalReply = Invoke-Control $finalAgent ([ordered]@{ action = 'status' }); break }
        catch { Start-Sleep -Milliseconds 250 }
    } while ([DateTime]::UtcNow -lt $until)
    if ($null -eq $finalReply) { throw 'final_agent_not_ready' }
    $script:phase = 'final_agent_status_validation'
    $script:finalStatus = Check-OfflineStatus $finalReply -RequireFolderSettings $true
    $script:phase = 'final_pair_update_validation'
    $invalid = Invoke-Control $finalAgent ([ordered]@{ action = 'pair_update'; id = 'acceptance-incomplete-pair' })
    if ($invalid.ok -ne $false -or [string]$invalid.error -cne 'Invalid folder request') { throw 'incomplete_pair_update_validation_not_rejected' }
    $script:invalidPairRejected = $true
    $script:phase = 'final_postvalidation_status'
    $afterInvalid = Check-OfflineStatus (Invoke-Control $finalAgent ([ordered]@{ action = 'status' }))
    if ($afterInvalid.authGeneration -ne $script:finalStatus.authGeneration -or $afterInvalid.folderSettingsSupported -ne $true) { throw 'invalid_pair_update_changed_agent_state' }
    Add-Event 'final_agent_capability' 'passed' @{ folderSettingsSupported = $script:finalStatus.folderSettingsSupported; incompletePairUpdateRejected = $true; connected = $script:finalStatus.connected; mounted = $script:finalStatus.mounted }

    $script:phase = 'final_agent_shutdown'
    $script:finalAgentExit = Stop-Agent
    if ($script:finalAgentExit -ne 0) { throw 'final_agent_shutdown_failed' }
    Add-Event 'final_agent_shutdown' 'passed' @{ exitCode = $script:finalAgentExit }
    $script:result = 'passed'
    Add-Event 'acceptance' 'passed' @{ transition = 'same-version candidate-to-final'; version = '0.7.4' }
} catch {
    $script:failure = $script:phase + ':' + $_.Exception.GetType().Name
    Add-Event $script:phase 'failed' @{ exceptionType = $_.Exception.GetType().Name }
} finally {
    if ($null -ne $script:agent) {
        try {
            $cleanupExit = Stop-Agent
            Add-Event 'agent_cleanup' 'passed' @{ exitCode = $cleanupExit }
        } catch {
            Add-Event 'agent_cleanup' 'failed' @{ exceptionType = $_.Exception.GetType().Name }
            $script:result = 'failed'
            if ($null -eq $script:failure) { $script:failure = 'agent_cleanup:' + $_.Exception.GetType().Name }
        }
    }
    if ($null -ne $script:startupAppData) { $env:APPDATA = $script:startupAppData }
    if ($null -ne $script:startupLocalAppData) { $env:LOCALAPPDATA = $script:startupLocalAppData }
    $receipt = [ordered]@{
        schema = 'raiun-windows-installed-package-acceptance-v1'
        result = $script:result
        failure = $script:failure
        platform = 'windows-2022-github-hosted'
        baselineSourceCommit = if ($script:baseline) { $script:baseline.sourceCommit } else { '1c60b4e6d7084ff5c3ba3f96b547d028e4c171cc' }
        finalSourceCommit = if ($script:final) { $script:final.sourceCommit } else { '26ccf130b3274d1f3ae9661b62bc19cb7cfd33b4' }
        baselineInstallerSha256 = if ($script:baseline) { $script:baseline.installerSha256 } else { $null }
        finalInstallerSha256 = if ($script:final) { $script:final.installerSha256 } else { $null }
        baselineInstallerExitCode = $script:baselineInstallExit
        busyAttemptExitCode = $script:busyInstallExit
        finalInstallerExitCode = $script:finalInstallExit
        sameUserSidSha256 = $script:sidHash
        baselineFiles = $script:baselineFiles
        finalFiles = $script:finalFiles
        busyGuard = ($null -ne $script:busyInstallExit -and $script:busyInstallExit -ne 0)
        registeredApp = $script:registration
        startMenuShortcuts = $script:shortcutCounts
        retainedData = $script:retained
        baselineAgentStatus = $script:baselineStatus
        finalAgentStatus = $script:finalStatus
        incompletePairUpdateRejected = $script:invalidPairRejected
        baselineAgentExitCode = $script:baselineAgentExit
        finalAgentExitCode = $script:finalAgentExit
        artifacts = [ordered]@{
            baseline = [ordered]@{ runId = 40463700987; artifactId = 12716153861; digest = 'sha256:dbe40aaad17370605aea25409e2a93ca30f879901502d21a7b458f7a30d962c5' }
            final = [ordered]@{ runId = 40504819643; artifactId = 12736215723; digest = 'sha256:25be0807fbdecfb12afa6eb8462873dae2460fd8aaa1d89362da31190d12e063' }
        }
        events = @($script:events.ToArray())
    }
    $json = ConvertTo-Json -InputObject $receipt -Depth 10
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'acceptance-receipt.json'), $json + "`n", [Text.UTF8Encoding]::new($false))
    if ((Get-Item -LiteralPath (Join-Path $OutputDirectory 'acceptance.log')).Length -gt 32768) { throw 'acceptance_log_exceeded_bound' }
}

if ($script:result -cne 'passed') { throw "Windows installed-package acceptance failed ($($script:failure))." }
