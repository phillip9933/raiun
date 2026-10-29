#!/usr/bin/env python3
"""Static/dry-run checks for the Windows per-user NSIS packaging contract."""

import json
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "desktop-shell/src-tauri/tauri.windows.conf.json"
PREPARE = ROOT / "scripts/prepare-windows-payload.ps1"
BUILD = ROOT / "scripts/build-windows-package.ps1"
PACKAGE_LOCK = ROOT / "desktop-shell/package-lock.json"
TAURI_SCHEMA = ROOT / "desktop-shell/node_modules/@tauri-apps/cli/config.schema.json"
WINDOWS_NOTICES = {
    "x86_64-pc-windows-msvc": ROOT / "legal/windows/dependency-inventory.json",
    "x86_64-pc-windows-gnullvm": ROOT / "legal/windows-gnullvm/dependency-inventory.json",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_target_notice_inventories() -> None:
    for target, path in WINDOWS_NOTICES.items():
        require(path.is_file(), f"missing target-scoped inventory: {path}")
        inventory = json.loads(path.read_text(encoding="utf-8"))
        require(inventory["target"] == target, f"notice inventory target mismatch: {target}")
        require(inventory["gaps"] == [], f"unresolved target notice gaps: {target}")
        expected_locks = {"Cargo.lock", "desktop-shell/src-tauri/Cargo.lock", "package-lock.json", "desktop-shell/package-lock.json"}
        require(set(inventory["lock_sha256"]) == expected_locks, f"notice inventory lock set mismatch: {target}")
        for lock_path, expected_hash in inventory["lock_sha256"].items():
            actual = hashlib.sha256((ROOT / lock_path).read_bytes()).hexdigest()
            require(actual == expected_hash, f"notice inventory is stale for {lock_path}")

        def verify(record: dict) -> None:
            notice_path = ROOT / record["path"]
            require(notice_path.is_file(), f"missing retained notice text: {notice_path}")
            data = notice_path.read_bytes()
            require(len(data) == record["bytes"], f"retained notice length mismatch: {notice_path}")
            require(hashlib.sha256(data).hexdigest() == record["sha256"], f"retained notice hash mismatch: {notice_path}")

        for package in inventory["rust_packages"] + inventory["production_ui_packages"]:
            for record in package["notice_files"]:
                verify(record)
        for record in inventory["first_party_notice_files"]:
            verify(record)
        verify(inventory["eme_notice"])
        for record in inventory["rust_toolchain_notices"]:
            verify(record)
        for tool in inventory["supplemental_build_tool_notices"]:
            for record in tool["notice_files"]:
                verify(record)

        external = inventory["bundled_external_artifact_review"]
        require(len(external) == 1 and external[0]["artifact"] == "WebView2Loader.dll", "bundled WebView2 loader review is missing")
        loader = external[0]
        require(loader["status"] == "verified" and loader["sdk_package"] == "Microsoft.Web.WebView2", "WebView2 SDK legal provenance is unresolved")
        require(loader["nuget_package_sha256"] == "56c9f26bdd07916a2d1949fb58a5c7e434dfa1173577dca879206050c4e718db", "unexpected WebView2 NuGet package hash")
        require(loader["loader_sha256"] == loader["matching_crate_loader_sha256"], "WebView2 loader does not match the reviewed SDK package")
        for record in (loader["license_file"], loader["notice_file"], loader["nuspec"], loader["package_provenance"]):
            verify(record)
        sdk_provenance = json.loads((ROOT / loader["package_provenance"]["path"]).read_text(encoding="utf-8"))
        require(sdk_provenance["nuget_nupkg_sha256"] == loader["nuget_package_sha256"] and
                sdk_provenance["nuget_nupkg_bytes"] == loader["nuget_package_bytes"] and
                sdk_provenance["nuget_version"] == loader["sdk_version"], f"WebView2 SDK provenance mismatch: {target}")
        provenance = inventory["webview2_rs_license_provenance"]
        require(len(provenance["crates"]) == 3, "version-pinned WebView2 Rust license provenance is incomplete")
        verify({"path": provenance["license_file"], "bytes": (ROOT / provenance["license_file"]).stat().st_size, "sha256": provenance["license_sha256"]})
        notice_doc = path.parent / "THIRD-PARTY-NOTICES.md"
        require(notice_doc.is_file() and target in notice_doc.read_text(encoding="utf-8"), f"target-specific notice document missing: {target}")


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
    $legal = Join-Path $repoRoot 'legal/windows'
    New-Item -ItemType Directory -Path $legal | Out-Null
    foreach ($name in @('LICENSE', 'NOTICE')) { Set-Content -LiteralPath (Join-Path $repoRoot $name) -Value ('fixture ' + $name) }
    foreach ($name in @('THIRD-PARTY-NOTICES.md', 'retained.txt')) { Set-Content -LiteralPath (Join-Path $legal $name) -Value ('fixture ' + $name) }
    $validInventory = [ordered]@{
        target = 'x86_64-pc-windows-msvc'
        gaps = @()
        bundled_external_artifact_review = @(@{ artifact = 'WebView2Loader.dll'; status = 'verified'; sdk_package = 'Microsoft.Web.WebView2'; sdk_version = '1.0.3800.47'; nuget_package_sha256 = ('a' * 64); nuget_package_bytes = 800; loader_sha256 = ('b' * 64); license_file = @{ path = 'legal/windows/retained.txt'; bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length; sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant() }; notice_file = @{ path = 'legal/windows/retained.txt'; bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length; sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant() }; nuspec = @{ path = 'legal/windows/retained.txt'; bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length; sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant() }; package_provenance = @{ path = 'legal/windows/provenance.json'; bytes = 0; sha256 = ('c' * 64) } })
        rust_packages = @(@{ name = 'fixture'; notice_files = @(@{ path = 'legal/windows/retained.txt'; bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length; sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant() }) })
        production_ui_packages = @()
        eme_notice = @{ path = 'legal/windows/retained.txt'; bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length; sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant() }
        rust_toolchain_notices = @()
        supplemental_build_tool_notices = @()
        first_party_notice_files = @()
        lock_sha256 = @{}
    }
    $inventoryPath = Join-Path $legal 'dependency-inventory.json'
    $lockFiles = @('Cargo.lock', 'desktop-shell/src-tauri/Cargo.lock', 'package-lock.json', 'desktop-shell/package-lock.json')
    foreach ($lock in $lockFiles) {
        $lockFile = Join-Path $repoRoot $lock
        New-Item -ItemType Directory -Path (Split-Path -Parent $lockFile) -Force | Out-Null
        Set-Content -LiteralPath $lockFile -Value ('synthetic ' + $lock)
        $validInventory.lock_sha256[$lock] = (Get-FileHash -LiteralPath $lockFile).Hash.ToLowerInvariant()
    }
    foreach ($name in @('LICENSE', 'NOTICE')) {
        $file = Join-Path $repoRoot $name
        $validInventory.first_party_notice_files += @{ path = $name; bytes = (Get-Item -LiteralPath $file).Length; sha256 = (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() }
    }
    $validInventory.first_party_notice_files += @{ path = 'legal/windows/THIRD-PARTY-NOTICES.md'; bytes = (Get-Item (Join-Path $legal 'THIRD-PARTY-NOTICES.md')).Length; sha256 = (Get-FileHash (Join-Path $legal 'THIRD-PARTY-NOTICES.md')).Hash.ToLowerInvariant() }
    $validInventory.bundled_external_artifact_review[0].license_file.bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length
    $validInventory.bundled_external_artifact_review[0].license_file.sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant()
    $validInventory.bundled_external_artifact_review[0].notice_file.bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length
    $validInventory.bundled_external_artifact_review[0].notice_file.sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant()
    $validInventory.bundled_external_artifact_review[0].nuspec.bytes = (Get-Item (Join-Path $legal 'retained.txt')).Length
    $validInventory.bundled_external_artifact_review[0].nuspec.sha256 = (Get-FileHash (Join-Path $legal 'retained.txt')).Hash.ToLowerInvariant()
    $sdkProvenance = @{ nuget_version = '1.0.3800.47'; nuget_nupkg_sha256 = ('a' * 64); nuget_nupkg_bytes = 800; x64_loader_sha256 = ('b' * 64) }
    $sdkProvenancePath = Join-Path $legal 'provenance.json'
    $sdkProvenance | ConvertTo-Json | Set-Content -LiteralPath $sdkProvenancePath
    $validInventory.bundled_external_artifact_review[0].package_provenance.bytes = (Get-Item $sdkProvenancePath).Length
    $validInventory.bundled_external_artifact_review[0].package_provenance.sha256 = (Get-FileHash $sdkProvenancePath).Hash.ToLowerInvariant()
    $validInventory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryPath
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
    $validInventory.gaps = @(@{ package = 'fixture'; reason = 'missing notice' })
    $validInventory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryPath
    $oldStageHash = (Get-FileHash -LiteralPath $sentinel).Hash
    $noticeFailed = $false
    try { & (Join-Path $scripts 'prepare-windows-payload.ps1') | Out-Null }
    catch { if ($_.Exception.Message -notmatch 'unresolved dependency notice gaps') { throw }; $noticeFailed = $true }
    if (-not $noticeFailed) { throw 'Unresolved Windows notice gaps must refuse staging.' }
    if ((Get-FileHash -LiteralPath $sentinel).Hash -cne $oldStageHash) { throw 'Notice failure replaced prior stage.' }
    $validInventory.gaps = @()
    $baselineInventory = $validInventory | ConvertTo-Json -Depth 12
    function Assert-NoticeInventoryReject([string] $Json, [string] $ExpectedMessage) {
        Set-Content -LiteralPath $inventoryPath -Value $Json
        $beforeStage = (Get-FileHash -LiteralPath $sentinel).Hash
        $rejected = $false
        try { & (Join-Path $scripts 'prepare-windows-payload.ps1') | Out-Null }
        catch {
            if ($_.Exception.Message -notmatch $ExpectedMessage) { throw }
            $rejected = $true
        }
        if (-not $rejected) { throw "Tampered Windows notice inventory was accepted: $ExpectedMessage" }
        if ((Get-FileHash -LiteralPath $sentinel).Hash -cne $beforeStage) { throw 'Notice validation failure replaced prior stage.' }
    }
    $badLock = $baselineInventory | ConvertFrom-Json
    $badLock.lock_sha256.PSObject.Properties['Cargo.lock'].Value = '0' * 64
    Assert-NoticeInventoryReject ($badLock | ConvertTo-Json -Depth 12) 'lock hash mismatch'
    $badLength = $baselineInventory | ConvertFrom-Json
    $badLength.rust_packages[0].notice_files[0].bytes++
    Assert-NoticeInventoryReject ($badLength | ConvertTo-Json -Depth 12) 'length mismatch'
    $badHash = $baselineInventory | ConvertFrom-Json
    $badHash.rust_packages[0].notice_files[0].sha256 = '0' * 64
    Assert-NoticeInventoryReject ($badHash | ConvertTo-Json -Depth 12) 'SHA-256 mismatch'
    $badSdkProof = $baselineInventory | ConvertFrom-Json
    $badSdkProof.bundled_external_artifact_review[0].license_file.sha256 = '0' * 64
    Assert-NoticeInventoryReject ($badSdkProof | ConvertTo-Json -Depth 12) 'SHA-256 mismatch'
    $badSdkProvenance = $baselineInventory | ConvertFrom-Json
    $badSdkProvenance.bundled_external_artifact_review[0].nuget_package_sha256 = '0' * 64
    Assert-NoticeInventoryReject ($badSdkProvenance | ConvertTo-Json -Depth 12) 'SDK provenance mismatch'
    $badFirstPartyNotice = $baselineInventory | ConvertFrom-Json
    $badFirstPartyNotice.first_party_notice_files[0].sha256 = '0' * 64
    Assert-NoticeInventoryReject ($badFirstPartyNotice | ConvertTo-Json -Depth 12) 'SHA-256 mismatch'
    $badRuntime = $baselineInventory | ConvertFrom-Json
    $badRuntime.eme_notice.bytes++
    Assert-NoticeInventoryReject ($badRuntime | ConvertTo-Json -Depth 12) 'length mismatch'
    Set-Content -LiteralPath $inventoryPath -Value $baselineInventory
    & (Join-Path $scripts 'prepare-windows-payload.ps1') | Out-Null
    $manifest = Get-Content -LiteralPath (Join-Path $stage 'payload-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.format -cne 'raiun-windows-payload-v2' -or $manifest.target -cne 'x86_64-pc-windows-msvc' -or $manifest.signed -ne $false -or @($manifest.payloads).Count -ne 2) { throw 'Payload manifest contract changed.' }
    if ($manifest.noticeInventory.target -cne 'x86_64-pc-windows-msvc' -or @($manifest.noticeInventory.files).Count -ne 8) { throw 'Windows notice inventory provenance was not pinned.' }
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
    test_target_notice_inventories()
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
    require(bundle["license"] == "AGPL-3.0-only", "Tauri bundle.license must use the first-party SPDX identifier")
    require(bundle["licenseFile"] == "../../LICENSE", "NSIS must include the first-party license file")
    schema = json.loads(TAURI_SCHEMA.read_text(encoding="utf-8"))
    bundle_properties = schema["definitions"]["BundleConfig"]["properties"]
    require("identifier" in bundle_properties["license"]["description"].lower(), "installed Tauri schema defines bundle.license as an identifier")
    require("path to the license file" in bundle_properties["licenseFile"]["description"].lower(), "installed Tauri schema defines bundle.licenseFile as a path")
    resources = bundle["resources"]
    require(resources == {
        "../../target/windows-package-resources/raiun-agent.exe": "raiun-agent.exe",
        "../../target/windows-package-resources/raiun.exe": "raiun.exe",
        "../../NOTICE": "NOTICE.txt",
        "../../legal/windows": "licenses",
    }, "Windows installer must bundle first-party attribution and the target-scoped legal inventory")
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
    require("unresolved dependency notice gaps" in prepare and "bundled_external_artifact_review" in prepare,
            "payload staging must fail closed for missing notices and unresolved bundled binaries")
    require("lock hash mismatch" in prepare and "SHA-256 mismatch" in prepare and "length mismatch" in prepare,
            "payload staging must validate recorded lock and retained-notice integrity values")
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
