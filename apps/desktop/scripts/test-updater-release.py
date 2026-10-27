from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DESKTOP_ROOT = Path(__file__).resolve().parent.parent
TAURI_CONFIG = DESKTOP_ROOT / "desktop-shell" / "src-tauri"


class UpdaterReleasePackagingTests(unittest.TestCase):
    def test_release_overlay_is_opt_in_and_matches_nsis_zip_contract(self) -> None:
        default = json.loads((TAURI_CONFIG / "tauri.conf.json").read_text(encoding="utf-8"))
        overlay = json.loads((TAURI_CONFIG / "tauri.updater-release.conf.json").read_text(encoding="utf-8"))
        windows_overlay = json.loads((TAURI_CONFIG / "tauri.updater-release-windows.conf.json").read_text(encoding="utf-8"))
        self.assertFalse(default["bundle"]["createUpdaterArtifacts"])
        self.assertIs(overlay["bundle"]["createUpdaterArtifacts"], True)
        self.assertEqual(windows_overlay["bundle"]["createUpdaterArtifacts"], "v1Compatible")
        self.assertNotIn("pubkey", overlay.get("plugins", {}).get("updater", {}))

    def test_linux_signer_is_after_final_repack_and_version_is_bound(self) -> None:
        script = (DESKTOP_ROOT / "scripts" / "build-appimage.sh").read_text(encoding="utf-8")
        repack = script.index('"$work/appimagetool" --appimage-extract-and-run')
        signer = script.index("signer sign --app-version", repack)
        audit = script.index("PYAUDIT", signer)
        self.assertLess(repack, signer)
        self.assertLess(signer, audit)
        self.assertIn('"$artifact"', script[signer : script.index("fi", signer)])
        self.assertIn("TAURI_SIGNING_PRIVATE_KEY_PATH", script)
        self.assertIn("RAIUN_DESKTOP_UPDATE_PUBKEY", script)
        self.assertIn('updater_artifacts="${RAIUN_DESKTOP_UPDATER_ARTIFACTS:-0}"', script)
        self.assertIn("RAIUN_DESKTOP_UPDATER_ARTIFACTS", script)
        self.assertIn('if [[ "$updater_release" == 1 ]]; then updater_artifacts=1; fi', script)
        self.assertLess(script.index("RAIUN_DESKTOP_UPDATE_PUBKEY"), script.index("cargo build"))
        artifact_mode = script.index('updater_artifacts="${RAIUN_DESKTOP_UPDATER_ARTIFACTS:-0}"')
        first_release_guard = script.index('if [[ "$updater_release" == 1 ]]; then', artifact_mode)
        private_guard = script.index('if [[ "$updater_release" == 1 ]]; then', first_release_guard + 1)
        self.assertLess(artifact_mode, private_guard)
        self.assertNotIn("TAURI_SIGNING_PRIVATE_KEY_PATH", script[artifact_mode:private_guard])
        self.assertIn("TAURI_SIGNING_PRIVATE_KEY_PATH", script[private_guard:script.index("mkdir -p", private_guard)])
        self.assertIn('TAURI_SIGNING_PRIVATE_KEY_PATH=$(realpath --', script)
        self.assertIn("--no-sign", script[script.index("if [[ \"$updater_artifacts\" == 1 ]]", script.index("tauri_args=")) : signer])
        self.assertIn("package.json, tauri.conf.json, and Cargo.toml versions to match", script)
        self.assertIn('[[ -s "$artifact.sig" ]]' , script)
        self.assertIn("updater_artifact_signature_status", script)
        self.assertIn("host_signing_required_before_update_install", script)
        self.assertLess(script.index('if [[ "$updater_release" == 1 ]]; then\n  # Tauri'), script.index('signer sign --app-version'))

    def test_windows_release_signs_nsis_updater_archive_not_setup_exe(self) -> None:
        script = (DESKTOP_ROOT / "scripts" / "build-windows-package.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch] $UpdaterArtifacts", script)
        self.assertIn("[switch] $UpdaterRelease", script)
        self.assertIn("$updaterArtifacts = $UpdaterArtifacts -or $UpdaterRelease", script)
        self.assertIn("RAIUN_DESKTOP_UPDATE_PUBKEY", script)
        self.assertIn("Initialize-UpdaterPublicKey -DesktopRoot $repoRoot", script)
        self.assertLess(script.index("Initialize-UpdaterPublicKey -DesktopRoot $repoRoot"), script.index("$updaterArtifacts ="))
        self.assertLess(script.index("Initialize-UpdaterPublicKey -DesktopRoot $repoRoot"), script.index("prepare-windows-payload.ps1"))
        self.assertIn("--no-sign", script)
        self.assertIn("src-tauri/tauri.updater-release.conf.json", script)
        self.assertIn("src-tauri/tauri.updater-release-windows.conf.json", script)
        self.assertIn("-Filter '*.nsis.zip'", script)
        self.assertIn("refuses to replace existing NSIS updater archives", script)
        self.assertIn("signer', 'sign', '--app-version'", script)
        self.assertIn("$updaterArchive.FullName", script)
        self.assertIn("[System.IO.Path]::GetFullPath($env:TAURI_SIGNING_PRIVATE_KEY_PATH)", script)
        self.assertIn("package.json and the Tauri shell Cargo package version", script)
        self.assertIn("signatureVersionBinding", script)
        self.assertIn("originalTauriArchiveName", script)
        self.assertIn("signatureStatus = if ($UpdaterRelease) { 'signed' } else { 'not_signed' }", script)
        self.assertIn("host signing required before update installation is available", script)
        self.assertIn("originalTauriArchiveSha256", script)
        self.assertIn("stagedUpdaterArchiveSha256", script)
        self.assertIn("raiun-desktop-windows-x86_64.nsis.zip", script)
        self.assertIn("signed = $false", script)
        self.assertIn("Tauri NSIS updater archive:", script)

    def test_windows_safe_archive_staging_preserves_bytes_and_fails_closed(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        script = (DESKTOP_ROOT / "scripts" / "build-windows-package.ps1").read_text(encoding="utf-8")
        start_marker = "# BEGIN safe updater archive staging"
        end_marker = "# END safe updater archive staging"
        self.assertEqual(script.count(start_marker), 1)
        self.assertEqual(script.count(end_marker), 1)
        helper = script.split(start_marker, 1)[1].split(end_marker, 1)[0]
        body = r'''
$ErrorActionPreference = 'Stop'
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('raiun-update-stage-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $source = Join-Path $root 'Raiun Desktop_0.7.0-beta.1_x64-setup.nsis.zip'
    $bytes = [byte[]](0, 1, 2, 3, 128, 255)
    [System.IO.File]::WriteAllBytes($source, $bytes)
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $destination = Join-Path $root 'fresh-output'
    $staged = Copy-NewUpdaterArchive -SourcePath $source -DestinationDirectory $destination `
        -DestinationName 'raiun-desktop-windows-x86_64.nsis.zip' -ExpectedSha256 $hash -ExpectedLength $bytes.Length
    if ($staged.Name -ne 'raiun-desktop-windows-x86_64.nsis.zip') { throw 'Staged archive basename is not the safe public name.' }
    if ([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($staged.FullName)) -cne [Convert]::ToBase64String($bytes)) { throw 'Staged archive bytes differ from the Tauri source archive.' }
    if (-not (Test-Path -LiteralPath $source)) { throw 'Original Tauri archive was removed.' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw 'Original Tauri archive bytes changed.' }

    $threw = $false
    try {
        Copy-NewUpdaterArchive -SourcePath $source -DestinationDirectory $destination `
            -DestinationName 'raiun-desktop-windows-x86_64.nsis.zip' -ExpectedSha256 $hash -ExpectedLength $bytes.Length | Out-Null
    } catch { $threw = $true }
    if (-not $threw) { throw 'Existing output directory should be rejected.' }

    [System.IO.File]::WriteAllBytes($staged.FullName, [byte[]](9, 9, 9))
    $threw = $false
    try {
        Assert-NewUpdaterArchiveCopy -SourcePath $source -DestinationPath $staged.FullName `
            -ExpectedSha256 $hash -ExpectedLength $bytes.Length | Out-Null
    } catch { $threw = $true }
    if (-not $threw) { throw 'Tampered staged bytes should fail readback verification.' }

    $badDestination = Join-Path $root 'bad-hash-output'
    $threw = $false
    try {
        Copy-NewUpdaterArchive -SourcePath $source -DestinationDirectory $badDestination `
            -DestinationName 'raiun-desktop-windows-x86_64.nsis.zip' -ExpectedSha256 ('0' * 64) -ExpectedLength $bytes.Length | Out-Null
    } catch { $threw = $true }
    if (-not $threw -or (Test-Path -LiteralPath $badDestination)) { throw 'Mismatched source hash should be rejected before staging.' }
    Write-Output 'Synthetic safe NSIS archive staging passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
'''
        with tempfile.TemporaryDirectory(prefix="raiun-update-stage-test-") as tmp:
            ps1 = Path(tmp) / "stage-test.ps1"
            ps1.write_text(helper + "\n" + body, encoding="utf-8")
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-File", str(ps1)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Synthetic safe NSIS archive staging passed.", result.stdout)

    def test_linux_public_key_defaults_from_trimmed_source_file_and_keeps_override(self) -> None:
        script = (DESKTOP_ROOT / "scripts" / "build-appimage.sh").read_text(encoding="utf-8")
        start_marker = "# BEGIN default updater public key"
        end_marker = "# END default updater public key"
        self.assertEqual(script.count(start_marker), 1)
        self.assertEqual(script.count(end_marker), 1)
        helper = script.split(start_marker, 1)[1].split(end_marker, 1)[0]
        official_key_path = DESKTOP_ROOT / "desktop-shell" / "update-public-key.pub"
        self.assertTrue(official_key_path.is_file())
        official_key = official_key_path.read_text(encoding="utf-8").strip()
        env = dict(os.environ)
        env.pop("RAIUN_DESKTOP_UPDATE_PUBKEY", None)
        result = subprocess.run(
            ["bash", "-c", helper + '\nroot="$1"; load_updater_public_key || exit 3; printf %s "$RAIUN_DESKTOP_UPDATE_PUBKEY"', "test", str(DESKTOP_ROOT)],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, official_key)
        with tempfile.TemporaryDirectory(prefix="raiun-public-key-linux-") as tmp:
            root = Path(tmp)
            key_path = root / "desktop-shell" / "update-public-key.pub"
            key_path.parent.mkdir()
            key_path.write_text("  fixture-public-key  \r\n", encoding="utf-8")
            for override, expected in ((None, "fixture-public-key"), ("fork-public-key", "fork-public-key")):
                env = dict(os.environ)
                env.pop("RAIUN_DESKTOP_UPDATE_PUBKEY", None)
                if override is not None:
                    env["RAIUN_DESKTOP_UPDATE_PUBKEY"] = override
                code = helper + '\nroot="$1"; load_updater_public_key || exit 3; printf %s "$RAIUN_DESKTOP_UPDATE_PUBKEY"'
                result = subprocess.run(["bash", "-c", code, "test", str(root)], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_windows_public_key_defaults_from_trimmed_source_file_and_keeps_override(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        script = (DESKTOP_ROOT / "scripts" / "build-windows-package.ps1").read_text(encoding="utf-8")
        start_marker = "# BEGIN default updater public key"
        end_marker = "# END default updater public key"
        self.assertEqual(script.count(start_marker), 1)
        self.assertEqual(script.count(end_marker), 1)
        helper = script.split(start_marker, 1)[1].split(end_marker, 1)[0]
        official_key_path = DESKTOP_ROOT / "desktop-shell" / "update-public-key.pub"
        self.assertTrue(official_key_path.is_file())
        official_key = official_key_path.read_text(encoding="utf-8").strip()
        env = dict(os.environ)
        env.pop("RAIUN_DESKTOP_UPDATE_PUBKEY", None)
        env["TEST_PUBLIC_KEY_ROOT"] = str(DESKTOP_ROOT)
        code = helper + '\nInitialize-UpdaterPublicKey -DesktopRoot $env:TEST_PUBLIC_KEY_ROOT; [Console]::Write($env:RAIUN_DESKTOP_UPDATE_PUBKEY)'
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", code], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, official_key)
        with tempfile.TemporaryDirectory(prefix="raiun-public-key-windows-") as tmp:
            root = Path(tmp)
            key_path = root / "desktop-shell" / "update-public-key.pub"
            key_path.parent.mkdir()
            key_path.write_text("  fixture-public-key  \r\n", encoding="utf-8")
            for override, expected in ((None, "fixture-public-key"), ("fork-public-key", "fork-public-key")):
                env = dict(os.environ)
                env.pop("RAIUN_DESKTOP_UPDATE_PUBKEY", None)
                if override is not None:
                    env["RAIUN_DESKTOP_UPDATE_PUBKEY"] = override
                code = helper + '\nInitialize-UpdaterPublicKey -DesktopRoot $env:TEST_PUBLIC_KEY_ROOT; [Console]::Write($env:RAIUN_DESKTOP_UPDATE_PUBKEY)'
                env["TEST_PUBLIC_KEY_ROOT"] = str(root)
                result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", code], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_artifact_only_mode_never_requires_or_invokes_signer(self) -> None:
        linux = (DESKTOP_ROOT / "scripts" / "build-appimage.sh").read_text(encoding="utf-8")
        self.assertIn("updater_artifacts=1", linux)
        linux_signer = linux.index('if [[ "$updater_release" == 1 ]]; then\n  # Tauri')
        linux_unsigned_notice = linux.index("Updater AppImage staged without a signature", linux_signer)
        self.assertLess(linux_signer, linux_unsigned_notice)
        self.assertIn("updater_signature_availability", linux)

        windows = (DESKTOP_ROOT / "scripts" / "build-windows-package.ps1").read_text(encoding="utf-8")
        self.assertIn("$updaterArtifacts = $UpdaterArtifacts -or $UpdaterRelease", windows)
        mode_start = windows.index("$updaterArtifacts = $UpdaterArtifacts -or $UpdaterRelease")
        payload_start = windows.index("prepare-windows-payload.ps1", mode_start)
        mode_block = windows[mode_start:payload_start]
        public_key_load = windows.index("Initialize-UpdaterPublicKey -DesktopRoot $repoRoot")
        self.assertLess(public_key_load, mode_start)
        private_guard = mode_block.index("if ($UpdaterRelease)")
        self.assertIn("TAURI_SIGNING_PRIVATE_KEY_PATH", mode_block[private_guard:])
        self.assertNotIn("TAURI_SIGNING_PRIVATE_KEY_PATH", mode_block[:private_guard])
        args_start = windows.index("$tauriArgs = @(")
        args_end = windows.index("$oldErrorActionPreference", args_start)
        self.assertIn("--no-sign", windows[args_start:args_end])
        self.assertNotIn("signer", windows[args_start:args_end])
        signer_at = windows.index("$signerArgs =")
        release_guard = windows.rfind("if ($UpdaterRelease)", 0, signer_at)
        self.assertGreater(release_guard, windows.index("if ($updaterArtifacts)", windows.index("$updaterArchive = $null")))
        self.assertIn("Updater archive staged without a signature", windows)
        self.assertIn("signatureStatus = if ($UpdaterRelease) { 'signed' } else { 'not_signed' }", windows)
        self.assertIn("signatureAvailability = 'host signing required before update installation is available'", windows)

    def test_windows_selector_synthetic_boundaries_with_powershell(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        script = (DESKTOP_ROOT / "scripts" / "build-windows-package.ps1").read_text(encoding="utf-8")
        start_marker = "# BEGIN updater archive selector"
        end_marker = "# END updater archive selector"
        self.assertEqual(script.count(start_marker), 1)
        self.assertEqual(script.count(end_marker), 1)
        helper = script.split(start_marker, 1)[1].split(end_marker, 1)[0]
        body = r'''
$ErrorActionPreference = 'Stop'
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('raiun-update-archive-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $setup = Join-Path $root 'Raiun-setup.exe'
    $zip = Join-Path $root 'Raiun-setup.nsis.zip'
    [System.IO.File]::WriteAllBytes($setup, [byte[]](1,2,3))
    [System.IO.File]::WriteAllBytes($zip, [byte[]](4,5,6))
    $selected = Get-ChangedNsisUpdaterArchive -BundleDirectory $root -PreviousHashes @{} -InstallerName 'Raiun-setup.exe'
    if ($selected.Name -ne 'Raiun-setup.nsis.zip') { throw 'Selected installer instead of updater archive.' }
    $other = Join-Path $root 'Other-setup.nsis.zip'
    [System.IO.File]::WriteAllBytes($other, [byte[]](7,8,9))
    $threw = $false
    try { Get-ChangedNsisUpdaterArchive -BundleDirectory $root -PreviousHashes @{} -InstallerName 'Raiun-setup.exe' | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected ambiguous changed archives to be refused.' }
    $threw = $false
    try { Get-ChangedNsisUpdaterArchive -BundleDirectory $root -PreviousHashes @{} -InstallerName 'Wrong-setup.exe' | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected a mismatched archive/setup basename to be refused.' }
    Write-Output 'Synthetic NSIS updater archive selection passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
'''
        with tempfile.TemporaryDirectory(prefix="raiun-update-archive-test-") as tmp:
            ps1 = Path(tmp) / "selector-test.ps1"
            ps1.write_text(helper + "\n" + body, encoding="utf-8")
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-File", str(ps1)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Synthetic NSIS updater archive selection passed.", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
