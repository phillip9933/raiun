# Embedded by raiun drive startup. The CLI supplies only escaped paths, mode,
# task identity and XML; no credential is included in this script or its argv.
$ErrorActionPreference = 'Stop'
if (-not $RaiunAction -or -not $RaiunTaskName -or -not $RaiunTaskXml) {
    throw 'Use raiun drive startup enable|disable|status to invoke this helper.'
}
# Pure binding admission is also exercised without Task Scheduler by the
# startup render smoke. The opaque name/marker is not sufficient by itself.
function Test-RaiunStartupTaskBinding {
    param($ExistingDefinition, $ExpectedDefinition, [string]$ExistingSid, [string]$CurrentSid)
    try {
        return ($ExistingSid -ceq $CurrentSid -and
            $ExistingDefinition.RegistrationInfo.Source -ceq $ExpectedDefinition.RegistrationInfo.Source -and
            $ExistingDefinition.Actions.Count -eq 1 -and
            $ExistingDefinition.Actions.Item(1).Path -ceq $ExpectedDefinition.Actions.Item(1).Path -and
            $ExistingDefinition.Actions.Item(1).Arguments -ceq $ExpectedDefinition.Actions.Item(1).Arguments -and
            $ExistingDefinition.Actions.Item(1).WorkingDirectory -ceq $ExpectedDefinition.Actions.Item(1).WorkingDirectory)
    } catch { return $false }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$existing = $null
try { $existing = $folder.GetTask($RaiunTaskName) }
catch {
    $lookupError = $_.Exception
    while ($null -ne $lookupError.InnerException) { $lookupError = $lookupError.InnerException }
    if ($lookupError.HResult -ne -2147024894) { throw 'Cannot inspect Task Scheduler; existing tasks were preserved.' }
}
[xml]$document = $RaiunTaskXml
foreach ($node in $document.SelectNodes("//*[local-name()='UserId']")) { $node.InnerText = $sid }
$definition = $service.NewTask(0)
$definition.XmlText = $document.OuterXml
if ($null -ne $existing) {
    $existingUser = $existing.Definition.Principal.UserId
    try {
        if ($existingUser -match '^S-[0-9]-') { $existingSid = (New-Object Security.Principal.SecurityIdentifier($existingUser)).Value }
        else { $existingSid = (New-Object Security.Principal.NTAccount($existingUser)).Translate([Security.Principal.SecurityIdentifier]).Value }
    } catch { throw 'The existing startup task account could not be verified; it was preserved.' }
    if (-not (Test-RaiunStartupTaskBinding $existing.Definition $definition $existingSid $sid)) {
        throw 'An unrelated or differently configured task uses this name. It was preserved; inspect it in Task Scheduler or choose separate headless state.'
    }
}
switch ($RaiunAction) {
    'Status' {
        if ($null -eq $existing) { Write-Output 'Startup task is not registered.'; break }
        $existingDefinition = $existing.Definition
        [pscustomobject]@{
            TaskName = $RaiunTaskName
            Enabled = $existing.Enabled
            State = $existing.State
            LastTaskResult = $existing.LastTaskResult
            LastRunTime = $existing.LastRunTime
            LogonType = $existingDefinition.Principal.LogonType
            UserSid = $sid
            Config = $RaiunConfig
            StateDirectory = $RaiunState
            RuntimeAcceptance = 'Boot DPAPI and Cloud Files acceptance pending; inspect raiun drive status separately.'
        } | Format-List
    }
    'Enable' {
        if (-not (Test-Path -LiteralPath $RaiunCli -PathType Leaf) -or -not (Test-Path -LiteralPath $RaiunConfig -PathType Leaf)) {
            throw 'The installed CLI and validated configuration must exist before startup is enabled.'
        }
        if ($RaiunMode -eq 'Boot' -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Boot-trigger registration requires an elevated terminal under this same Windows account. Reopen PowerShell as administrator and rerun; no startup task was changed.'
        }
        $registered = $null
        if ($RaiunMode -eq 'Boot') {
            Write-Output 'Windows Task Scheduler will store this account credential securely for password logon. Enter the account password, not the Windows Hello PIN or an OpenCloud token.'
            $credential = Get-Credential -UserName $identity.Name -Message 'Raiun boot startup: Windows account password (hidden)'
            if ($null -eq $credential) { throw 'Credential prompt cancelled; startup task was not changed.' }
            $bstr = [IntPtr]::Zero
            try {
                $account = New-Object Security.Principal.NTAccount($credential.UserName)
                if ($account.Translate([Security.Principal.SecurityIdentifier]).Value -cne $sid) {
                    throw 'The startup credential must belong to the current Windows account.'
                }
                if ($credential.Password.Length -eq 0) { throw 'Boot startup requires a nonempty Windows account password.' }
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
                try {
                    $registered = $folder.RegisterTaskDefinition($RaiunTaskName, $definition, 6, $identity.Name,
                        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr), 1, $null)
                } catch {
                    throw 'Boot task registration failed. Verify the current account password, same-user elevation and Log on as a batch job policy; no credential was written by Raiun.'
                }
            } finally {
                if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                $credential.Password.Dispose()
                $credential = $null
            }
        } else {
            try { $registered = $folder.RegisterTaskDefinition($RaiunTaskName, $definition, 6, $sid, $null, 3, $null) }
            catch { throw 'Logon task registration failed; verify same-user Task Scheduler permissions.' }
        }
        try { $null = $registered.Run($null) }
        catch { throw 'Startup was registered, but immediate task launch failed. Inspect the task status; configuration and state were preserved.' }
        Write-Output "Enabled $RaiunTaskName ($RaiunMode) and requested immediate start."
        Write-Output 'Verify task and drive status. Noninteractive boot DPAPI/Cloud Files acceptance remains pending; registration alone does not prove a working mount.'
    }
    'Disable' {
        if ($null -eq $existing) { Write-Output 'No matching startup task exists; configuration and state were preserved.'; break }
        # Close startup/restart admission before requesting normal agent stop.
        # Never use Task.Stop or forced process termination on an active drive.
        $existing.Enabled = $false
        & $RaiunCli --config $RaiunConfig drive --state-dir $RaiunState --json stop
        if ($LASTEXITCODE -ne 0) {
            throw 'Startup is disabled, but safe agent stop could not be confirmed (the agent may already be offline). The disabled task registration, configuration and state were preserved. Inspect drive status before removing the task manually.'
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(330)
        do {
            $current = $folder.GetTask($RaiunTaskName)
            if ($current.State -ne 4 -and $current.State -ne 2) { break }
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'Startup is disabled, but the task has not finished safe shutdown. Registration and state were preserved; no process was forcibly terminated.'
            }
            Start-Sleep -Seconds 1
        } while ($true)
        $folder.DeleteTask($RaiunTaskName, 0)
        Write-Output 'Startup task removed after safe shutdown. Configuration, credentials, registrations and local files were preserved.'
    }
    default { throw 'Unknown Raiun startup action.' }
}
