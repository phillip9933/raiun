#!/usr/bin/env python3
"""Static/dry-run checks for the Windows per-user NSIS packaging contract."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "desktop-shell/src-tauri/tauri.windows.conf.json"
PREPARE = ROOT / "scripts/prepare-windows-payload.ps1"
BUILD = ROOT / "scripts/build-windows-package.ps1"
PACKAGE_LOCK = ROOT / "desktop-shell/package-lock.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_nsis_shell_marker_helper(build: str) -> None:
    begin = "# BEGIN NSIS shell pin helper"
    end = "# END NSIS shell pin helper"
    require(build.count(begin) == 1 and build.count(end) == 1, "NSIS shell pin helper boundaries must be unique")
    helper = build.split(begin, 1)[1].split(end, 1)[0]
    require("function Get-NsisShellExecutablePath" in helper, "shell helper must derive the executable from the selected bundle directory")
    require("$bundle.Parent.Parent" in helper, "shell helper must resolve the executable beside the selected NSIS bundle")
    require("Join-Path $targetDir 'release\\raiun-desktop-shell.exe'" not in build, "shell path must not be hard-coded to the native target layout")
    require("__TAURI_BUNDLE_TYPE_VAR_UNK" in helper and "__TAURI_BUNDLE_TYPE_VAR_NSS" in helper, "shell helper must pin the observed raw and NSIS markers")
    require("exactly one unknown Tauri bundle-type marker" in helper, "shell helper must fail closed for missing or repeated markers")
    require("already contains the NSIS bundle-type marker" in helper, "shell helper must fail closed for an already-patched raw input")
    require("bundledExpectedSha256" in build and "rawRelease" in build and "bundledExpected" in build, "manifest must distinguish raw and bundled shell pins")

    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        return

    test_body = r'''
$ErrorActionPreference = 'Stop'
function Assert-Throws([byte[]] $InputBytes) {
    $threw = $false
    try { Get-NsisShellMetadata -ShellBytes $InputBytes | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected helper to reject invalid marker input.' }
}
function Assert-BundlePathThrows([string] $BundleDirectory) {
    $threw = $false
    try { Get-NsisShellExecutablePath -BundleDirectory $BundleDirectory | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected path helper to reject an unexpected bundle layout.' }
}
$tempRoot = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('raiun-layout-' + [guid]::NewGuid().ToString('N')))
$nativeBundle = [System.IO.Path]::Combine($tempRoot, 'target', 'release', 'bundle', 'nsis')
$tripleBundle = [System.IO.Path]::Combine($tempRoot, 'target', 'x86_64-pc-windows-msvc', 'release', 'bundle', 'nsis')
$nativeShell = Get-NsisShellExecutablePath -BundleDirectory $nativeBundle
$tripleShell = Get-NsisShellExecutablePath -BundleDirectory $tripleBundle
if ($nativeShell -ne [System.IO.Path]::Combine($tempRoot, 'target', 'release', 'raiun-desktop-shell.exe')) { throw 'Native target shell path mismatch.' }
if ($tripleShell -ne [System.IO.Path]::Combine($tempRoot, 'target', 'x86_64-pc-windows-msvc', 'release', 'raiun-desktop-shell.exe')) { throw 'Explicit target shell path mismatch.' }
Assert-BundlePathThrows ([System.IO.Path]::Combine($tempRoot, 'target', 'bundle', 'nsis'))
$prefix = 'fixture:'
$suffix = ':end'
$raw = [System.Text.Encoding]::ASCII.GetBytes($prefix + '__TAURI_BUNDLE_TYPE_VAR_UNK' + $suffix)
$metadata = Get-NsisShellMetadata -ShellBytes $raw
$expected = [System.Text.Encoding]::ASCII.GetBytes($prefix + '__TAURI_BUNDLE_TYPE_VAR_NSS' + $suffix)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $expectedHash = [System.BitConverter]::ToString($sha.ComputeHash($expected)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
if ($metadata.rawLength -ne $raw.Length -or $metadata.bundledExpectedLength -ne $raw.Length) { throw 'Length metadata mismatch.' }
if ($metadata.bundledExpectedSha256 -ne $expectedHash) { throw 'Derived NSIS shell hash mismatch.' }
Assert-Throws ([System.Text.Encoding]::ASCII.GetBytes($prefix + ':no-marker'))
Assert-Throws ([System.Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_UNK/__TAURI_BUNDLE_TYPE_VAR_UNK'))
Assert-Throws ([System.Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_NSS'))
Write-Output 'NSIS shell marker helper synthetic boundaries passed.'
'''
    with tempfile.TemporaryDirectory(prefix="raiun-nsis-shell-test-") as temp_dir:
        script_path = Path(temp_dir) / "test-nsis-shell-helper.ps1"
        script_path.write_text(helper + "\n" + test_body, encoding="utf-8")
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-File", str(script_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    require(result.returncode == 0, f"PowerShell shell-marker helper test failed: {result.stdout}\n{result.stderr}")
    require("synthetic boundaries passed" in result.stdout, "PowerShell shell-marker helper test did not report success")



def test_payload_cargo_target_routing(prepare: str, build: str) -> None:
    def extract(text: str, label: str) -> str:
        begin, end = f"# BEGIN {label}", f"# END {label}"
        require(text.count(begin) == 1 and text.count(end) == 1, "target resolver boundaries must be unique")
        return text.split(begin, 1)[1].split(end, 1)[0]

    payload_resolver = extract(prepare, "payload Cargo target resolver")
    package_normalizer = extract(build, "package Cargo target normalization")
    require("--target-dir $payloadTargetDir" in prepare, "Cargo must use the resolved payload target")
    require("$sourceDir = Join-Path $payloadTargetDir 'x86_64-pc-windows-msvc\\release'" in prepare,
            "payload source lookup must use the exact same target as Cargo")
    require("$stageDir = Join-Path $repoRoot 'target\\windows-package-resources'" in prepare,
            "Tauri resources must keep their existing local staging contract")
    require(build.index("# END package Cargo target normalization") < build.index("& (Join-Path $PSScriptRoot 'prepare-windows-payload.ps1')"),
            "relative target normalization must precede payload preparation")
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    require(powershell is not None, "PowerShell is required for actual target-routing contracts")
    def literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"
    body = r"""
$ErrorActionPreference = 'Stop'
$oldTarget = $env:CARGO_TARGET_DIR
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('raiun-target-contract-' + [guid]::NewGuid().ToString('N'))
$repoRoot = Join-Path $tempRoot 'repo with spaces'
$elsewhere = Join-Path $tempRoot 'different cwd'
New-Item -ItemType Directory -Path $repoRoot,$elsewhere | Out-Null
try {
    $cases = @(
        @{ configured = $null; expected = (Join-Path $repoRoot 'target') },
        @{ configured = (Join-Path $tempRoot 'shared absolute cache'); expected = (Join-Path $tempRoot 'shared absolute cache') },
        @{ configured = 'relative-cache'; expected = (Join-Path $repoRoot 'relative-cache') },
        @{ configured = 'relative cache with spaces'; expected = (Join-Path $repoRoot 'relative cache with spaces') }
    )
    foreach ($case in $cases) {
        $env:CARGO_TARGET_DIR = $case.configured
        # Script blocks return their exact resolved value explicitly below.
        $actual = & $payloadResolver
        if ($actual -cne $case.expected) { throw 'Standalone payload target mismatch.' }
        . $packageNormalizer
        if ($null -eq $case.configured) {
            if (-not [string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) { throw 'Unset target default changed.' }
        } elseif ($env:CARGO_TARGET_DIR -cne $case.expected) { throw 'Package target normalization mismatch.' }
        Push-Location $elsewhere
        try {
            $afterCwd = & $payloadResolver
            if ($afterCwd -cne $case.expected) { throw 'Payload and package targets diverged after cwd change.' }
        } finally { Pop-Location }
    }
    # Invoke the real preparation script against harmless fake tool commands.
    # Cargo failure must stop BEFORE creating/replacing any staged resources.
    $scripts = Join-Path $repoRoot 'scripts'
    New-Item -ItemType Directory -Path $scripts | Out-Null
    Copy-Item -LiteralPath $preparePath -Destination (Join-Path $scripts 'prepare-windows-payload.ps1')
    $fakeCargo = Join-Path $tempRoot 'fake-cargo.ps1'
    $fakeRustc = Join-Path $tempRoot 'fake-rustc.ps1'
    $global:TargetTestArgumentLog = Join-Path $tempRoot 'cargo-arguments.json'
    Set-Content -LiteralPath $fakeCargo -Value '$args | ConvertTo-Json | Set-Content -LiteralPath $global:TargetTestArgumentLog; $global:LASTEXITCODE = 17'
    Set-Content -LiteralPath $fakeRustc -Value 'Write-Output "host: x86_64-pc-windows-msvc"; $global:LASTEXITCODE = 0'
    function Get-Command {
        [CmdletBinding()] param([string] $Name)
        switch ($Name) {
            'cargo.exe' { [pscustomobject]@{ Source = $fakeCargo } }
            'rustc.exe' { [pscustomobject]@{ Source = $fakeRustc } }
            'cl.exe' { [pscustomobject]@{ Source = 'C:\VC\Tools\MSVC\bin\cl.exe' } }
            'link.exe' { [pscustomobject]@{ Source = 'C:\VC\Tools\MSVC\bin\link.exe' } }
            default { throw 'Unexpected tool command.' }
        }
    }
    $stage = Join-Path $repoRoot 'target/windows-package-resources'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $sentinel = Join-Path $stage 'previous-public-payload.txt'
    Set-Content -LiteralPath $sentinel -Value 'preserve prior stage'
    $before = (Get-FileHash -LiteralPath $sentinel).Hash
    $env:CARGO_TARGET_DIR = Join-Path $tempRoot 'shared absolute cache'
    $failed = $false
    try { & (Join-Path $scripts 'prepare-windows-payload.ps1') | Out-Null }
    catch { if ($_.Exception.Message -notmatch 'exit code 17') { throw }; $failed = $true }
    if (-not $failed) { throw 'Failed Cargo must refuse payload staging.' }
    if ((Get-FileHash -LiteralPath $sentinel).Hash -cne $before) { throw 'Cargo failure replaced prior stage.' }
    if (@(Get-ChildItem (Join-Path $repoRoot 'target') -Directory -Filter 'windows-package-resources.tmp-*').Count) { throw 'Cargo failure created staging.' }
    $arguments = @(Get-Content -LiteralPath $global:TargetTestArgumentLog -Raw | ConvertFrom-Json)
    $index = [array]::IndexOf([string[]] $arguments, '--target-dir')
    if ($index -lt 0 -or $arguments[$index + 1] -cne $env:CARGO_TARGET_DIR) { throw 'Actual Cargo invocation ignored configured shared target.' }
    # A successful fake build must copy from that SAME shared target, not stale
    # similarly named files in the repository default target.
    $sharedRelease = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc/release'
    $staleRelease = Join-Path $repoRoot 'target/x86_64-pc-windows-msvc/release'
    New-Item -ItemType Directory -Path $sharedRelease,$staleRelease -Force | Out-Null
    foreach ($name in @('raiun-agent.exe', 'raiun.exe')) {
        [IO.File]::WriteAllBytes((Join-Path $sharedRelease $name), [Text.Encoding]::UTF8.GetBytes('public fresh fixture ' + $name))
        [IO.File]::WriteAllBytes((Join-Path $staleRelease $name), [Text.Encoding]::UTF8.GetBytes('wrong stale cache ' + $name))
    }
    Set-Content -LiteralPath $fakeCargo -Value '$args | ConvertTo-Json | Set-Content -LiteralPath $global:TargetTestArgumentLog; $global:LASTEXITCODE = 0'
    & (Join-Path $scripts 'prepare-windows-payload.ps1') | Out-Null
    $manifest = Get-Content -LiteralPath (Join-Path $stage 'payload-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.target -cne 'x86_64-pc-windows-msvc' -or $manifest.signed -ne $false -or @($manifest.payloads).Count -ne 2) { throw 'Payload manifest contract changed.' }
    foreach ($row in $manifest.payloads) {
        $sharedHash = (Get-FileHash -LiteralPath (Join-Path $sharedRelease $row.name)).Hash.ToLowerInvariant()
        $stagedHash = (Get-FileHash -LiteralPath (Join-Path $stage $row.name)).Hash.ToLowerInvariant()
        if ($sharedHash -cne $stagedHash -or $row.sha256 -cne $sharedHash -or $row.length -ne (Get-Item (Join-Path $stage $row.name)).Length) { throw 'Copied payload or manifest came from stale/default target.' }
    }
    Write-Output 'Actual target routing and failed-Cargo staging contracts passed.'
} finally {
    $env:CARGO_TARGET_DIR = $oldTarget
    Remove-Variable TargetTestArgumentLog -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
"""
    # Resolver block is actual production code; return only its output variable.
    script = ("$preparePath = " + literal(str(PREPARE)) + "\n"
              + "$payloadResolver = {\n" + payload_resolver + "\n$payloadTargetDir\n}\n"
              + "$packageNormalizer = {\n" + package_normalizer + "\n}\n" + body)
    with tempfile.TemporaryDirectory(prefix="raiun-payload-target-test-") as temp_dir:
        path = Path(temp_dir) / "target-contract.ps1"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(path)],
                                capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0, f"PowerShell target-routing contract failed: {result.stdout}\n{result.stderr}")
    require("Actual target routing and failed-Cargo staging contracts passed." in result.stdout,
            "Actual target-routing test did not report success")
    print(result.stdout.strip())


def main() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    bundle = config["bundle"]
    require(bundle["targets"] == ["nsis"], "Windows config must build NSIS only")
    require(bundle["icon"] == ["icons/icon.ico"], "Windows installer must use the Windows icon")
    nsis = bundle["windows"]["nsis"]
    require(nsis["installMode"] == "currentUser", "installer must be per-user")
    require(nsis["startMenuFolder"] == "Raiun", "Start Menu folder must be configured")
    require(nsis["template"] == "./windows/installer.nsi", "installer must use the reviewed in-place-upgrade template")
    require(nsis["installerHooks"] == "./windows/installer-hooks.nsh", "installer must use the safe process-use guard")
    require(nsis["customLanguageFiles"]["English"] == "./windows/English.nsh", "installer must explain in-place upgrades in its default language")
    resources = bundle["resources"]
    require(set(resources.values()) == {"raiun-agent.exe", "raiun.exe"}, "both companion binaries must be resources")
    require(all(source.startswith("../../target/windows-package-resources/") for source in resources), "resources must come from isolated build staging")
    require(not any(path.startswith("resources/") for path in resources.values()), "companion files must be installed beside the shell")
    require(not (ROOT / "desktop-shell/src-tauri/packaging/windows/installer-hooks.nsh").exists(), "obsolete companion-copy hook should not return")
    require(not (ROOT / "packaging/windows/installer-hooks.nsh").exists(), "obsolete companion-copy hook must not return")
    cli_version = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))["packages"]["node_modules/@tauri-apps/cli"]["version"]
    require(cli_version == "2.12.1", "custom NSIS template is pinned to Tauri CLI 2.12.1")
    template = (ROOT / "desktop-shell/src-tauri/windows/installer.nsi").read_text(encoding="utf-8")
    hooks = (ROOT / "desktop-shell/src-tauri/windows/installer-hooks.nsh").read_text(encoding="utf-8")
    language = (ROOT / "desktop-shell/src-tauri/windows/English.nsh").read_text(encoding="utf-8")
    hook_code = "\n".join(line for line in hooks.splitlines() if not line.lstrip().startswith(";"))
    require("tauri-cli-v2.12.1" in template and "Based on Tauri CLI 2.12.1" in template, "custom template must identify its exact upstream source")
    reinstall_page = template.split("Function PageReinstall", 1)[1].split("FunctionEnd", 1)[0]
    require("StrCpy $ReinstallPageCheck 2" in reinstall_page, "first-time upgrades must default to the keep-existing-install choice")
    require(reinstall_page.index("StrCpy $ReinstallPageCheck 2") < reinstall_page.index("SendMessage $R3 ${BM_SETCHECK}"), "upgrade default must select the in-place radio choice")
    require(reinstall_page.index("SendMessage $R3 ${BM_SETCHECK}") < reinstall_page.index("${NSD_SetFocus} $R3") < reinstall_page.index("${NSD_SetFocus} $R2"), "keyboard focus must follow the selected reinstall choice")
    install_section = template.split("Section Install", 1)[1].split("SectionEnd", 1)[0]
    require("!insertmacro RaiunCheckInstallProcesses" in install_section, "install must use the safe no-force shutdown check")
    require("CheckIfAppIsRunning" not in install_section, "install must not use Tauri's forced Restart Manager shutdown")
    require(install_section.index("!insertmacro RaiunCheckInstallProcesses") < install_section.index('File "${MAINBINARYSRCPATH}"'), "process guard must run before replacing the shell")
    require("RmDir /r" not in install_section and "CurrentVersion\\Run" not in install_section, "direct upgrade must not delete user data or alter startup preference")
    require("Call RestorePreviousInstallLocation" in template and 'WriteRegStr SHCTX "${MANUPRODUCTKEY}" "" $INSTDIR' in install_section, "direct upgrade must preserve Tauri's per-user install location identity")
    require("!insertmacro CheckIfAppIsRunning" in template.split("Section Uninstall", 1)[1], "explicit uninstall behavior must remain Tauri's standard behavior")
    require(all(name in hooks for name in ("RestartManager_RegisterFile", "${MAINBINARYNAME}.exe", "raiun-agent.exe", "raiun.exe")), "upgrade guard must check every installed executable")
    require("RSTRTMGR::RmGetList(i R0, *i .r1, *i 0r2, p 0, *i .r3) i .r4" in hook_code, "Restart Manager process count must be explicitly initialized to zero")
    require("RestartManager_StartSession $R0" in hooks and "RestartManager_EndSession $R0" in hooks, "Restart Manager session handle must remain in R0 through every path")
    require("RmGetList" in hook_code and "RmForceShutdown" not in hook_code and "RmShutdown(" not in hook_code, "upgrade guard must detect and never stop processes")
    require("MB_RETRYCANCEL" in hooks and "Quit Raiun Desktop" in hooks, "running processes must get a normal-quit retry or cancel prompt")
    require("Upgrade in place (recommended)" in language and "Uninstall and reinstall" in language, "upgrade copy must clearly explain the default and alternate option")

    prepare = PREPARE.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")
    test_nsis_shell_marker_helper(build)
    test_payload_cargo_target_routing(prepare, build)
    require("-p raiun-agent -p raiun-cli" in prepare, "payload preparation must build the agent and CLI")
    require("Get-FileHash" in prepare and "sha256" in prepare, "payload staging must record hashes")
    require("$ErrorActionPreference = 'Continue'" in prepare and "$buildExitCode = $LASTEXITCODE" in prepare, "Cargo stderr must not abort PowerShell before exit status is checked")
    require("prepare-windows-payload.ps1" in build, "package helper must prepare the sidecar payload first")
    require("$npmExitCode = $LASTEXITCODE" in build and "$tauriExitCode = $LASTEXITCODE" in build, "npm and Tauri failures must be checked by native exit code")
    require("'--bundles', 'nsis'" in build and "src-tauri/tauri.windows.conf.json" in build, "package helper must use the Windows NSIS config")
    require("CARGO_TARGET_DIR" in build and "x86_64-pc-windows-msvc\\release\\bundle\\nsis" in build, "package helper must find bundles under the active Cargo target directory")
    require("VersionOverride" in build and "windows-package-version-override.json" in build, "package helper must support an isolated upgrade-version overlay")
    require("--no-sign" in build and "raiun-windows-installer-v1" in build, "package helper must preserve unsigned provenance")
    require("signed = $false" in prepare, "payload manifest must identify unsigned binaries")
    docs = (ROOT / "docs/WINDOWS-PACKAGING.md").read_text(encoding="utf-8")
    require("per-user" in docs, "documentation must describe the per-user behavior")
    require("tauri-cli-v2.12.1" in docs, "documentation must link the reviewed Tauri NSIS template")
    print("Windows packaging contract dry-run passed; no installer was built or executed.")


if __name__ == "__main__":
    main()
