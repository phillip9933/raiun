# Windows package preparation

The Windows package is an unsigned, per-user NSIS installer. Build it from a
Visual Studio Developer PowerShell with the x86_64 MSVC Rust toolchain, Node.js,
and npm available:

```powershell
.\scripts\build-windows-package.ps1
```

The helper builds `raiun-agent.exe` and `raiun.exe` for the MSVC target, stages
them with SHA-256 metadata under the ignored `target/windows-package-resources`
directory, builds the Tauri shell, and asks Tauri to produce only the NSIS
installer. Use the helper rather than invoking Tauri directly so the declared
resource inputs exist before bundling. The Tauri resource map installs both
companions at the application directory root beside the shell. The shell can
therefore launch its sibling `raiun-agent.exe`; the CLI is also available as
`raiun.exe` for support and diagnostics. Tauri's generated NSIS uninstaller
removes each mapped resource at its declared target path, so the companion
files do not need a separate copy or uninstall hook. This is the behavior of
the [Tauri CLI 2.12.1 NSIS template](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.12.1/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi)
pinned in `package-lock.json`: its install section copies mapped resources
under `$INSTDIR`, and its uninstall section deletes those same target paths.

The pinned template defaults a first-time version upgrade to the existing
installation instead of selecting the uninstall option. Before copying any
executable, the installer checks whether the installed shell, agent, or CLI
still has its files open. If so, it asks the user to quit Raiun normally and
retry or cancel; it does not terminate processes automatically. The in-app
updater continues to use its existing verified handoff.

Set `CARGO_TARGET_DIR` to retain build artifacts across filtered source copies.
The helper uses that target for both the Agent/CLI build and payload lookup,
and resolves a relative setting against the desktop repository root before
changing directories. Resource staging stays under the source copy's ignored
`target/windows-package-resources`. Without the setting, existing defaults
apply. Use one build at a time for a shared target directory.

The installer writes to the current user's installation directory and creates
a Raiun Start Menu entry. It does not register login autostart. By default, the
uninstaller removes application files and shortcuts while preserving account,
cache, and recovery state. Tauri's standard NSIS uninstaller also offers an
explicit “Delete app data” checkbox, which is unchecked by default. It targets
Tauri's `%APPDATA%\org.raiun.desktop` and `%LOCALAPPDATA%\org.raiun.desktop`
directories; the agent's `%LOCALAPPDATA%\Raiun` account, cache, and recovery
state is outside those targets. Upgrades do not remove user state.

The static contract check is safe to run on any host:

```text
python scripts/test-windows-packaging.py
```

It validates the NSIS mode, bundled agent/CLI root-level resource mapping,
unsigned manifest, and absence of a custom companion-copy hook.
PowerShell contracts also check target routing, refusal to stage after a failed
Cargo command, and payload selection when stale default-target files exist.
It does not build or execute an installer. Native install, upgrade, launch, and
uninstall-preserves-state checks still require a Windows VM. This workflow does
not sign or publish a package.

For the synthetic in-place upgrade check, build the second installer with a
temporary version overlay, for example
`.\scripts\build-windows-package.ps1 -VersionOverride 0.1.1` when the
configured version is `0.1.0`. The helper stores the overlay under the ignored
target directory and removes it after the build; it does not edit the canonical
Tauri or npm version.

## Windows VM acceptance

Run acceptance under a fresh ordinary test account with only synthetic local
state and no production sign-in. Install the unsigned package and verify the
shell, `raiun-agent.exe`, and `raiun.exe` are present at the same install root;
compare companion hashes to the package manifest and run their help commands.
Launch the shell while disconnected, then close it without signing in.

Place synthetic sentinel files under `%LOCALAPPDATA%\Raiun` for an account
record, cached data, recovery journal, and a local `OpenCloud` root. Perform an
in-place higher-version upgrade and verify their lengths and hashes are
unchanged. Uninstall with the default unchecked “Delete app data” option and
verify the install directory and Start Menu entry are removed while all four
sentinels remain. Record the test account, installer hash, companion hashes,
upgrade result, and post-uninstall sentinel hashes. This acceptance must not
connect to a real account or cloud service.
