# Harmless environment regression only: never runs Raiun, mounts, or startup.
param([string]$RunnerPath = (Join-Path $PSScriptRoot 'test-headless-mount-windows.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $RunnerPath).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Native runner PowerShell syntax is invalid.' }
$helper = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-FixtureProcessEnvironment' }, $true))
if ($helper.Count -ne 1) { throw 'Expected exactly one native runner environment helper.' }
. ([scriptblock]::Create($helper[0].Extent.Text))
$keys = @('RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD','RAIUN_HEADLESS_CONTEXT','RAIUN_HEADLESS_CONFIG','RAIUN_STATE_DIR')
$fixtureKey = 'RAIUN_HEADLESS_NATIVE_FIXTURE_DIR'
$saved = @{}
foreach ($name in ($keys + $fixtureKey)) {
    $saved[$name] = @{ present=[Environment]::GetEnvironmentVariables('Process').Contains($name); value=[Environment]::GetEnvironmentVariable($name,'Process') }
}
$checks = 0
try {
    foreach ($initial in @($null, '', 'synthetic-inherited-state')) {
        foreach ($name in $keys) {
            Set-FixtureProcessEnvironment $name $initial
            Set-FixtureProcessEnvironment $name $null
            if ([Environment]::GetEnvironmentVariables('Process').Contains($name)) { throw 'Routing key remains present after removal.' }
            $checks++
        }
        # A path with spaces is passed without command-line interpolation.
        $fixture = Join-Path ([IO.Path]::GetTempPath()) 'synthetic fixture with spaces'
        Set-FixtureProcessEnvironment $fixtureKey $fixture
        $info = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        foreach ($arg in @('-NoProfile','-NonInteractive','-Command', '$keys=@("RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD","RAIUN_HEADLESS_CONTEXT","RAIUN_HEADLESS_CONFIG","RAIUN_STATE_DIR"); $present=@($keys|Where-Object{[Environment]::GetEnvironmentVariables("Process").Contains($_)}); @{routing_keys_present=$present.Count;fixture=[Environment]::GetEnvironmentVariable("RAIUN_HEADLESS_NATIVE_FIXTURE_DIR","Process")}|ConvertTo-Json -Compress')) { $info.ArgumentList.Add($arg) }
        $child = [Diagnostics.Process]::Start($info)
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(10000)) { throw 'Harmless environment probe timed out.' }
        $result = $stdout.GetAwaiter().GetResult() | ConvertFrom-Json
        if ($child.ExitCode -ne 0 -or $result.routing_keys_present -ne 0 -or $result.fixture -cne $fixture) { throw 'Child environment routing/path regression.' }
        if ($stderr.GetAwaiter().GetResult().Length -ne 0) { throw 'Harmless child reported an error.' }
        $checks++
    }
} finally {
    foreach ($name in $saved.Keys) {
        if ($saved[$name].present) { Set-FixtureProcessEnvironment $name $saved[$name].value }
        else { Set-FixtureProcessEnvironment $name $null }
    }
}
foreach ($name in $saved.Keys) {
    $present = [Environment]::GetEnvironmentVariables('Process').Contains($name)
    $value = [Environment]::GetEnvironmentVariable($name,'Process')
    if ($present -ne $saved[$name].present -or ($present -and $value -cne $saved[$name].value)) { throw 'Parent environment was not restored exactly.' }
}
[pscustomobject]@{passed=$true;checks=$checks;parent_restored=$true;powershell=$PSVersionTable.PSVersion.ToString();native_mount_attempted=$false} | ConvertTo-Json -Compress
