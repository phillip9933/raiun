# Evaluate only the pure binding-admission function; never execute helper
# top-level code, load Task Scheduler, register a task, or access credentials.
param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference = 'Stop'
$startupErrors = $null
$startupTokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$startupTokens, [ref]$startupErrors)
if ($startupErrors.Count) { throw 'Startup helper has syntax errors.' }
$functions = $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-RaiunStartupTaskBinding'}, $true)
if ($functions.Count -ne 1) { throw 'Expected one pure task-binding admission function.' }
. ([ScriptBlock]::Create($functions[0].Extent.Text))
function New-SyntheticTaskDefinition {
    param([string]$Marker='RaiunHeadlessCLI-v1:synthetic', [string]$Executable='C:\Raiun\raiun.exe',
        [string]$Arguments='--config "C:\Raiun\config.json" drive --state-dir "C:\Raiun\state" serve',
        [string]$WorkingDirectory='C:\Raiun', [int]$ActionCount=1)
    $action = [pscustomobject]@{Path=$Executable; Arguments=$Arguments; WorkingDirectory=$WorkingDirectory}
    $actions = [pscustomobject]@{Count=$ActionCount; SyntheticAction=$action}
    $actions | Add-Member -MemberType ScriptMethod -Name Item -Value {param($index) if($index -ne 1){throw 'Only exact first action admitted'}; return $this.SyntheticAction}
    return [pscustomobject]@{RegistrationInfo=[pscustomobject]@{Source=$Marker}; Actions=$actions}
}
$expected = New-SyntheticTaskDefinition
$currentSid = 'S-1-5-21-1000'
if (-not (Test-RaiunStartupTaskBinding $expected $expected $currentSid $currentSid)) { throw 'Exact synthetic binding refused.' }
$wrongDefinitions = @(
    (New-SyntheticTaskDefinition -Marker 'RaiunDesktop'),
    (New-SyntheticTaskDefinition -Executable 'C:\Other\raiun.exe'),
    (New-SyntheticTaskDefinition -Arguments '--config C:\Other\config.json drive serve'),
    (New-SyntheticTaskDefinition -WorkingDirectory 'C:\Other'),
    (New-SyntheticTaskDefinition -ActionCount 2),
    (New-SyntheticTaskDefinition -ActionCount 0),
    $null
)
foreach ($wrong in $wrongDefinitions) {
    if (Test-RaiunStartupTaskBinding $wrong $expected $currentSid $currentSid) { throw 'Foreign or malformed task binding admitted.' }
}
if (Test-RaiunStartupTaskBinding $expected $expected 'S-1-5-21-2000' $currentSid) { throw 'Foreign task account admitted.' }
'Pure task-binding tests passed: exact admitted, eight foreign/malformed cases refused; no Scheduler or credentials used.'
