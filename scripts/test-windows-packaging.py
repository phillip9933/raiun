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


def main() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    bundle = config["bundle"]
    require(bundle["targets"] == ["nsis"], "Windows config must build NSIS only")
    require(bundle["icon"] == ["icons/icon.ico"], "Windows installer must use the Windows icon")
    nsis = bundle["windows"]["nsis"]
    require(nsis["installMode"] == "currentUser", "installer must be per-user")
    require(nsis["startMenuFolder"] == "Raiun", "Start Menu folder must be configured")
    resources = bundle["resources"]
    require(set(resources.values()) == {"raiun-agent.exe", "raiun.exe"}, "both companion binaries must be resources")
    require(all(source.startswith("../../target/windows-package-resources/") for source in resources), "resources must come from isolated build staging")
    require(not any(path.startswith("resources/") for path in resources.values()), "companion files must be installed beside the shell")
    require("installerHooks" not in bundle.get("windows", {}).get("nsis", {}), "no copy/uninstall hook should bypass Tauri's resource file list")
    require(not (ROOT / "packaging/windows/installer-hooks.nsh").exists(), "obsolete companion-copy hook must not return")
    cli_version = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))["packages"]["node_modules/@tauri-apps/cli"]["version"]
    require(cli_version == "2.12.1", "reviewed NSIS resource/uninstall behavior is pinned to Tauri CLI 2.12.1")

    prepare = PREPARE.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")
    test_nsis_shell_marker_helper(build)
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
