# Windows and CachyOS VM testing

## Lab connection preflight

The owner confirmed on 16 October that NAS SSH requires the `root` account.
This is the NAS management connection; native Linux tests still run as the
isolated ordinary guest user. Confirm the configured host, existing host-key
verification and available authentication with a read-only connection before
starting a transfer. Do not disable host-key verification to repair access.
Connection configuration must not contain passwords or be included in source
bundles. A temporary configuration under `/tmp` can disappear independently of
the VM or its preserved test data; its absence is an access blocker, not a
revocation of the owner's standing testing and transfer approval.

## Runtime evidence and copied-profile preflight

Guest execution may start in `/`. Never derive mutation scope from `$PWD`, a
login-shell home, or an unchecked empty variable. Use explicit absolute test
paths. Prefer setting ownership at directory creation and per-file staging;
recursive ownership/permission changes require a resolved-path check against the
exact test subtree and must never cross its mount boundary. Keep failures fatal;
do not mask a scope or permission failure with `|| true`. On 16 October an
unchecked recursive chown affected the isolated guest; all affected disks were
preserved and the OS restored before acceptance resumed. See R22's incident
record rather than attempting speculative ownership repair.

Capture subprocess stdout/stderr directly to files and record exit codes. Generate
the digest inventory in the guest, then verify exported bytes. A hand-written
summary or remembered output is never raw evidence. Preserve failed attempts and
label missing captures honestly; recapture a narrowly justified test when needed.
Keep session/keyring secrets out of logs and source bundles.

Run Cargo gates as the isolated ordinary test user with explicit `CARGO_HOME`
and `RUSTUP_HOME` pointing to that user's installed toolchain. Record `id` and
`cargo --version` under that same environment before launching gates; QGA's root
shell does not inherit the user's Rustup default. Keep the working environment
in the test runner instead of rediscovering it for each release.

Before copying source, targets, packages or profiles, create the intended staging
parent and record `findmnt -T` plus `df -B1` for that exact resolved path. A free-space
check on a nearby additive mount does not prove that a sibling directory is on
that mount. Keep all staging children beneath the verified mount; repeat this
check for the effective profile and build target before starting tests. On the
current CachyOS VM, `/home/raiun-offline16/r18-data` is the additive disk;
`/home/raiun-offline16/r19-data` is on the root disk and is not a substitute.

Before launching a copied synthetic profile, inspect the effective nested
`settings.config.cloud_root` and the exact state directory selected by the
launcher. Rewrite every copied fixture/log path to the new test location. Check
the running `/proc/<pid>/exe` hash, not just the staged package file.

For permission recovery, record exact stat paths and modes for both the cloud
root and its `Personal` child. The synthetic cloud root is intentionally 0555;
the expected transition is `Personal` 0555 offline to 0755 after validated
reconnect. Record the same agent PID and FUSE mount ID before/after, then test a
synthetic write/readback. Restarting online does not satisfy this reconnect gate.
Preserve pin/recovery hashes and confirm owned mount/process cleanup.

## Windows multiple-placeholder gate — 13 October 2026 JST

Exact source `290b8de77a668772d160c12d1c799895de25c3815a6edc03662cb8342f33a45a`
passed SDK layout checks, ten adapter tests, synthetic registration/cleanup,
multiple-folder/file enumeration, and strict Windows Clippy. The live test
confirmed two FETCH_DATA callbacks with runtime ParamSize 64 and 12,288 bytes
transferred and verified. Validation accepts only documented 60 or observed
aligned 64; Linux compilation alone cannot validate this Windows-only code.

The run used SYSTEM and internally owned synthetic roots. It does not establish
real OpenCloud provider integration, ordinary-user Explorer acceptance, writes,
or offline policy support on Windows. Evidence is in desktop
`outputs/vm-lab/cfapi-param-gate-20261012-r20/`. The VM is shut off and NAS counters
remained 63/50 with other counters zero. No laptop update for this gate.

## Windows restart restoration gate — 12 October 2026

Source `d0e362df8c6078c3fd80a1299172738d462ff97fd0a759714d3e397c4a123f9d`
passed 27 Windows agent tests, 10 control/DPAPI tests and strict Clippy.
The synthetic SYSTEM-context gate validates exact-profile/server/client session
restoration from a bounded protected pointer, identity/expiry rejection, and
individual cleanup-failure paths. It does not validate ordinary-user desktop UI,
Windows drive integration, or every simultaneous storage-failure scenario.
The VM is shut down; NAS counters remained 63/50, others zero. Evidence:
`outputs/vm-lab/windows-session-restore-20261012/` from the project root.
The Linux laptop remains on the previously verified 04:07:35 UTC build.

## Windows sign-in gate — 12 October 2026

Frozen source r6 (`0ee6b5771fbfe9ddd6730bd8db689b97227f9aa4f3535f878ec3b79f2979f433`)
passed 21 Windows agent tests, nine Windows control/DPAPI tests, and strict
Clippy in the Windows VM. Tests cover synthetic OAuth/PKCE, session persistence,
and cancellation after persistence but before connected-state publication.
They ran as SYSTEM, not an interactive ordinary user. Windows drive support,
restart session restore, and native user-session acceptance remain incomplete.
The VM is shut down; NAS counters remained 63/50 with other counters zero.
Evidence: `repo/outputs/vm-lab/windows-auth-20261012/` from the project root.
No new laptop package was installed for this Windows-only gate.

## Current verification checkpoint — 12 October 2026

The latest completed Linux gate is the subtree-reservation build dated
`2026-10-12T02:03:19Z`: 425 workspace tests, 13 shell tests, 12 live mount tests,
strict Clippy, formatting, frontend/installer gates, and isolated package smoke
passed in CachyOS. That exact package was installed on the laptop at 02:54 UTC;
the app was already closed and remains closed. Evidence is in
`repo/outputs/vm-lab/subtree-reservations-20261012/` relative to the project root.

Newer nested offline encrypted-folder dependency work has passed source tests
and is awaiting its own exact-source VM/package gate. The Windows OAuth/DPAPI
sign-in slice is awaiting Windows compilation and synthetic runtime checks;
Windows drive/provider integration and restart session restore are incomplete.
Earlier SYSTEM adapter checks do not establish ordinary-user GUI acceptance.
Synthetic Linux Secret Service save/lookup/lock denial/removal passed, but
interactive unlock prompts remain unverified.

The owner explicitly authorized continued isolated VM testing despite the NAS
NVMe issues. The current observed corruption-counter baseline is 63/50, replacing
the older 63/49 baseline below. No storage repair or counter reset is authorized
by that testing decision. Historical records below describe their own run dates.

This guide records the Raiun Desktop test VMs on Unraid. It covers portable Rust and Linux integration checks; it does not change platform support. Linux is the only desktop integration path. Windows has no native Raiun provider or supported agent startup.

## Current lab state

Both VMs are installed on `PPLFS1` (`192.168.3.99`). Both were cleanly shut down after the 10 October 2026 encrypted-sync validation. They use Unraid's default NAT network (`192.168.122.0/24`), have no host shares or disk passthrough, and have autostart disabled.

| VM | vCPU | RAM | Thin disk | Guest NAT address |
| --- | --- | --- | --- | --- |
| `raiun-test-cachyos` | 4 | 8 GiB | 80 GiB | `192.168.122.215` |
| `raiun-test-windows11` | 4 | 8 GiB | 96 GiB | `192.168.122.203` |

Open their consoles from the NAS VM page. VNC listeners are bound to the NAS loopback interface.

### Storage incident and mitigation

Initial direct-I/O runs produced Btrfs checksum failures on inode `70499038`, the Windows `system.qcow2`, and guest disk I/O errors. Both guests were cleanly shut down. SMART reports PASS with zero media errors on both SSDs; offline `qemu-img check` passed both images' structural checks. A full offline read of the Windows image completed with Btrfs read recovery. These checks do not identify the underlying cause or prove all guest data intact.

Before resuming, offline preservation copies of disk, firmware and domain XML were saved as `pre-buffered-20261009` under each guest's directory, with Windows TPM state included. These are same-pool recovery copies, not independent backups or registered snapshots. Earlier CachyOS `clean-os` and `test-ready` copies remain unchanged. Final passing states were saved offline under each guest’s `verified-20261009` directory, including Windows TPM state; both copies passed `qemu-img check`. These baselines record the tested lab state, not proof that the entire NAS pool is healthy.

Only the lab VM disk configuration was changed: `cache=writethrough`, `io=threads`, and read/write error policy `stop`. This uses buffered synchronous I/O and pauses a guest if QEMU reports another disk error. No checksum disabling, pool repair, scrub, host reboot, or production-service changes were performed. The [libvirt disk driver documentation](https://libvirt.org/formatdomain.html#hard-drives-floppy-disks-cdroms) describes these settings. Btrfs documents the [interaction between direct I/O and checksumming](https://btrfs.readthedocs.io/en/stable/Checksumming.html); that is a possible mechanism, not an established root cause on this host.

Monitored reruns have shown no new QEMU disk errors or counter increases (baseline: `nvme1n1p1` 63, `nvme0n1p1` 49). Windows read-only CHKDSK also completed with no filesystem problems. Retain the counters and logs; do not reset them to conceal the incident. Stop lab workloads if counters increase or a VM pauses for I/O, and investigate the host before resuming. A pool-wide health assessment remains separate from these bounded lab checks.

## Windows 11

The guest is Windows 11 Enterprise Evaluation build `26300.9457`, installed from Microsoft's [Evaluation Center media](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise). First-user OOBE is pending. Secure Boot is confirmed disabled; virtual TPM 2.0 is present, ready, and enabled. Complete OOBE under Microsoft's evaluation terms before user-session testing.

On 10 October 2026, the portable encryption suite passed **143 tests** from an isolated source tree under `C:\RaiunLab\encryption-20261010\repo`, using a separate target directory. Counts were CLI 10, core 28, engine 19, OpenCloud unit 29, OpenCloud engine integration 3, encrypted-backend integration 7, vault-creation integration 2, vault-readonly integration 1, vault unit 26, vault interoperability 12, and vault-write integration 6. The suite ran as `SYSTEM` through QEMU Guest Agent, with the existing MSVC and Rust toolchains. The complete native output is preserved outside the repository in `windows-portable-tests.log` (maintainer-local evidence: `../../outputs/vm-lab/encryption-20261010/windows-portable-tests.log`). The synthetic encrypted-backend tests use local fixtures; no live OpenCloud account or server was used. The run does not verify Windows native provider, tray, or signed-in user-session behavior.

On 12 October 2026, the isolated `raiun-control-windows` adapter was compiled and tested as `WORKGROUP\SYSTEM` through QEMU Guest Agent, using Rust 1.99.0 and Visual Studio 2022 Developer PowerShell 17.14.41. All **9 adapter tests passed**, including a 65,536-byte DPAPI round-trip, profile/server/client identity isolation, protected-store save/replace/remove, and named-pipe protocol tests. The minimal two-crate test bundle and captured output are in `windows-dpapi-20261012` (maintainer-local evidence: `../../outputs/vm-lab/windows-dpapi-20261012/`). This is synthetic SYSTEM coverage only: the adapter is not wired into Raiun, and it does not validate an interactive user profile or OOBE. Strict Clippy was unavailable because the VM toolchain lacks that component; it was not installed. The NAS had no noVNC/websockify bridge; the VM VNC listener remained loopback-only and was not exposed. No user was created.

The VM exposed three portability issues: test fixtures using Unix-style filesystem roots, engine path/flush handling on Windows, and atomic publication over an open temporary destination. The engine now releases its temporary handle during backend publication while retaining pathname cleanup ownership, then reopens the published file. Regression tests verify published bytes and cleanup after both success and a failed download. The HTTP fixture explicitly switches accepted sockets to blocking mode. Existing replacement, no-clobber, and recovery behavior is retained. This coverage does not establish Windows native-provider acceptance.

For a healthy Windows VM, the portable test prerequisites are Rust stable for `x86_64-pc-windows-msvc`, Visual Studio Build Tools with the C++ workload, and a Windows SDK. The repository toolchain and test scripts are `scripts/provision-windows-test-tools.ps1` and `scripts/test-windows-vm.ps1`.

## CachyOS

The guest runs CachyOS with KDE, GRUB/UEFI, kernel `7.2.9-1-cachyos`, and the `plasmalogin` service. Test jobs ran as the non-root `raiun-test` user; the latest transient service was `raiun-tests-final-v2.service`. These one-shot services are not a recurring schedule.

The earlier 9 October Linux run, with portability fixes, passed 123 workspace tests, 6 shell checks, and the opt-in live FUSE roundtrip. Its tested package was `outputs/vm-lab/raiun-desktop-cachyos-20261009-embedded-ui-x86_64.tar.gz` (outside the repository), SHA-256 `8294d563c9dbd4830e70fd78820e2a974d775cf4b3c42b1e6cce58bb6bb89bca`. Earlier artifacts remain preserved separately. The historical `cachyos/test-ready` copy contains toolchains and build caches.

The 10 October encrypted-sync candidate was tested from `/home/raiun-test/encryption-20261010/source`. Workspace formatting and strict Clippy passed; all **219 workspace tests** passed. Both explicitly requested synthetic FUSE tests passed in a separate run, the frontend production build passed, and all **8 Tauri shell tests** passed. The runner reported `TEST_RESULT=PASS`. The package `/home/raiun-test/raiun-desktop-linux-encrypted-sync-20261010-x86_64.tar.gz` has SHA-256 `90a9c6db7aa42dcd0f6643237d57a758bc0cd17f0aeb646cce4d2e52415f31da`.

The account UI follow-up candidate was validated on 10 October 2026. Its source changes update the selected account summary on successful status refresh and leave duplicate/overlap root checks to the agent's canonical validation. The exact candidate `outputs/packages/raiun-desktop-linux-account-ui-20261010-x86_64.tar.gz` has SHA-256 `da93f0882d59e5eb6fcc0625dcc93b4f91fb54d423751b596a2aeb063b611f47` (manifest timestamp `2026-10-10T03:55:04Z`, commit `2e6df1550e01f0c803aca4e35e1a3a50c390f770`, dirty source tree). It was copied to the guest and the hash matched.

The candidate installer accepted the archive and installed only beneath `/home/raiun-test/account-ui-20261010/isolated-xdg-data`. All four executable/icon payload hashes matched the manifest. The packaged `raiun` and `raiun-agent` help commands worked. With fresh synthetic XDG config/state/cache/runtime directories, the packaged agent started, returned disconnected status with no server or session, and stopped. Current frontend sources and lockfile were copied to a separate fresh directory; `npm ci` and the TypeScript/Vite production build passed after the referenced `src-tauri/icons/raiun.svg` asset was added to that source copy. Rust workspace and shell suites were not repeated because only frontend files changed; the preceding 219 workspace, 8 shell, and 2 synthetic FUSE checks remain the relevant code gates.

No native window was launched: the guest SSH environment had no `DISPLAY` or `WAYLAND_DISPLAY`, neither Xvfb nor Weston was present, and listed sessions were the greeter and headless user managers. This run does not validate native account switching, sign-out, tray behavior, portal scaling, or desktop autostart. No real account or server was used. The VM was gracefully shut down afterward. NAS Btrfs counters before, during, and after remained at corruption counts 63 and 49, with all other listed counters zero. Logs and summary are preserved in `outputs/vm-lab/account-ui-20261010` (maintainer-local evidence: `../../outputs/vm-lab/account-ui-20261010/`).

The encrypted-sync candidate was installed as `raiun-test` using a fresh `XDG_DATA_HOME` under `/home/raiun-test/encryption-20261010/isolated-install-data`; no system install or prior application data was used. The four installed payload hashes matched the archive manifest. `raiun --help` and `raiun-agent --help` worked. With separate synthetic XDG config/state/cache/runtime directories and `RAIUN_STATE_DIR`, the installed agent started, answered a local status request as disconnected with no server or session, and was stopped. No real account or server was used. The evidence and raw runner output are preserved in `outputs/vm-lab/encryption-20261010` (maintainer-local evidence: `../../outputs/vm-lab/encryption-20261010/`).

The per-Space folder-sync controls candidate was validated on 10 October 2026 from `/home/raiun-test/space-controls-20261010/source`. Workspace formatting and strict Clippy passed; all **226 workspace tests** passed, with two host-dependent FUSE tests ignored by the ordinary suite. The shell passed formatting and all **9 shell tests**; `npm ci` and the frontend production build passed. Candidate `outputs/packages/raiun-desktop-linux-space-controls-20261010-x86_64.tar.gz` has SHA-256 `b0c264b33a416088d98cb78e4b1470b43d04ec19dbbebc56bc5aa4fc36bbf08b` (manifest timestamp `2026-10-10T04:33:04Z`, commit `2e6df1550e01f0c803aca4e35e1a3a50c390f770`, dirty source tree). The source archive SHA-256 was `b0f4e57edcaa927c0bdd9d83e73317aadb9e29e18929db87b4ea079cad168747`.

The exact archive was installed only beneath `/home/raiun-test/space-controls-20261010/isolated-xdg-data`; all four executable/icon payload hashes matched its manifest. Packaged CLI and agent help worked. With fresh synthetic config/state/cache/runtime paths and no server or account, the packaged agent reported `connected: false` and `paused_space_ids: []`, then acknowledged graceful shutdown and removed its control socket. No graphical session was available, so the native window and interactive per-Space controls were not exercised. The two synthetic FUSE tests were not repeated for this UI/IPC follow-up. No real account or server was used. The guest shut down gracefully. NAS Btrfs counters before, during, and after remained at corruption counts 63 and 49, with all other listed counters zero. Logs and summary are preserved in `outputs/vm-lab/space-controls-20261010` (maintainer-local evidence: `../../outputs/vm-lab/space-controls-20261010/`).

For the encrypted-sync run, the native window was not launched: the SSH environment had no `DISPLAY` or `WAYLAND_DISPLAY`, and neither Xvfb nor Weston was installed; the listed sessions included only the greeter and headless user sessions. That run therefore does not verify native window/tray behavior, the portal chooser, or desktop-login autostart. Parent monitoring reported the Btrfs counters unchanged at 63 and 49; the lab logs and counters should remain preserved.


## Folder-vault browse and diagnostics candidate (10 October 2026)

The final r2 Linux candidate, `outputs/packages/raiun-desktop-linux-vault-browse-r2-20261010-x86_64.tar.gz`, has SHA-256 `4128554c2253e487c95a2cd6cfb1a9fc401024f4ca6b02a9505f3a721af7fda3`. Its manifest records build timestamp `2026-10-10T05:16:52Z`, commit `2e6df1550e01f0c803aca4e35e1a3a50c390f770`, and `dirty=true`. The source archive used for the full workspace run has SHA-256 `2f01fd2f504769062b0d8810e2f4f48af22dc74e4ee9829a774fc13128cbf9a9`; after that run, only `desktop-shell/src/main.ts` changed. That final file (SHA-256 `2687f4ca50602c8b74029f599a1700afff8846c103fd5b483127339855ffda9c`) was rebuilt with the production frontend command and is included as `frontend-main-r2.ts` in the evidence directory.

On CachyOS, workspace formatting and strict Clippy passed, all **240 workspace tests** passed (three host-dependent FUSE tests were ignored by the ordinary run), and all **9 Tauri shell tests** passed. The production frontend build passed for both the source bundle and final r2 UI. All three ignored live synthetic FUSE tests then passed: folder-vault read-only browse with open-handle revocation after lock, FUSE roundtrip, and dual-profile mount isolation with exact owned cleanup. The exact r2 archive was installed beneath a fresh isolated XDG data directory; the archive hash and all four payload hashes matched. Packaged `raiun` and `raiun-agent` help worked. A synthetic valid config containing path/ID canaries produced diagnostics with none of the canaries; malformed synthetic JSON produced only `parse_valid: false` and null counts, also without leaking its canary. The installed agent returned disconnected status with no server or session and `paused_space_ids: []`, then acknowledged shutdown and removed its control socket. No real account, server, or user data was used.

The guest was gracefully shut down after testing. Btrfs counters before, during, and after remained at corruption counts 63 and 49; all other listed counters remained zero. No graphical session was launched, so this gate does not validate native window, tray, or portal behavior. Raw logs and synthetic outputs are preserved in `outputs/vm-lab/vault-browse-20261010` (maintainer-local evidence: `../../outputs/vm-lab/vault-browse-20261010/`).

To reproduce the Linux checks after storage health is established, use a clean checkout with Rust, Node.js/npm, GTK 3, WebKitGTK 4.1, Ayatana AppIndicator, and FUSE development packages installed:

```sh
scripts/test-linux-vm.sh
```

The automated checks do not cover full desktop acceptance, sign-in, mount restoration, or autostart. The live FUSE check uses temporary test data and requires `/dev/fuse` inside the guest.

## Official setup references

- [Microsoft Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) and [download page](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise)
- [Microsoft: Automate Windows Setup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/automate-windows-setup?view=windows-11)
- [Unraid: Windows VMs](https://docs.unraid.net/unraid-os/using-unraid-to/create-virtual-machines/windows-on-a-vm/) and [VM setup](https://docs.unraid.net/unraid-os/using-unraid-to/create-virtual-machines/vm-setup/)
- [CachyOS downloads and ISO validation](https://wiki.cachyos.org/cachyos_basic/download/) and [installation guide](https://wiki.cachyos.org/installation/installation_on_root/)

## Repeating a lab run

The scripts are one-shot jobs, not a recurring schedule. Start the guests from Unraid's VM page after checking host storage counters. For CachyOS, SSH access uses the private `../private/vm-lab/ssh-config` file from the project container; it is not committed. Run `scripts/test-linux-vm.sh` as `raiun-test` inside `/home/raiun-test/raiun-desktop`. For explicit live FUSE coverage, run:

```sh
cargo test -p raiun-fuse live_fuse_roundtrip_when_device_is_available -- --ignored --nocapture
```

For Windows user-session runs after OOBE, provision the current user's tools from elevated PowerShell, then run `scripts/test-windows-vm.ps1` from Developer PowerShell. The existing lab runner uses the SYSTEM toolchain under `C:\RaiunLab`; invoke it through QEMU Guest Agent and retain `guest-exec-status` stdout/stderr. It is not a substitute for testing an ordinary signed-in desktop user.

Before a Windows UI harness runs, check the exact script in Windows PowerShell
5.1: parse it, compile its embedded C#, and use reflection to verify that every
PowerShell static-method call resolves to a public method with matching reference
argument types. Compilation alone does not check those call sites. Exercise
collector output shapes without UI input, and install the error recorder before
validation. Retain process handles before an action and persist its input result
and numeric exit as soon as observed, before optional collection can fail.

Window presence, focus and closure must be observed in the actual interactive
WTS session. SYSTEM/Session 0 window queries cannot establish Session 1 absence.
A foreground mismatch alone also does not make a screenshot unusable: inspect
the actual image for occlusion and keep focus identity separate from window
ownership. An uncertain action is never repeated merely to repair its evidence;
collect read-only state, preserve missing exit codes as unavailable, and proceed
only when the next action’s own safety conditions are established.

## Release UI packaging correction

The initial tested package omitted Tauri’s `custom-protocol` feature and therefore attempted to load the development URL at `127.0.0.1:1420`. Build/unit tests alone did not catch that packaging error. `scripts/build-linux.sh` now explicitly enables the feature so production UI assets are embedded, while development builds retain their dev-server workflow. The corrected package passed the full Linux checks and was installed and launched on the laptop; the unchanged background agent was left running. Manual visual acceptance remains a separate check. The `verified-20261009` VM copies predate this packaging correction; the current CachyOS disk includes it.


## Parent directory revocation follow-up — 10 October 2026

The isolated CachyOS source snapshot SHA-256
`5d22f37d5234d63e792988bb643eb6cbf17ce74e7dfb63caa8e8a20506a48771`
passed formatting, strict workspace Clippy, 242 workspace tests and all three
separately enabled live FUSE tests. The extended encrypted-folder test opens two
ordinary Personal directory snapshots without consuming them, checks rejection
after lock and after re-unlock, and checks fresh listings hide/show the vault.
It does not claim to retract names already returned into userspace buffers.
Evidence is in `directory-revocation-20261010` (maintainer-local evidence: `../../outputs/vm-lab/directory-revocation-20261010/`).
The guest was gracefully shut down; NAS corruption counters stayed 63/49 and
all other counters stayed zero. No package or laptop installation changed.
Whole-Space routes remain disabled; native UI and live-server acceptance remain
separate outstanding gates.

## Account setup UI and mount-default candidate (10 October 2026)

The isolated account-setup source snapshot (`/tmp/raiun-account-setup-source.tar.gz`, SHA-256 `28e5b0a2a3340e52a4bd2d046ed8b10da8eda74a9fb8b84076d644008041a7ff`) passed `cargo fmt --all --check`, strict workspace Clippy, and **243 workspace tests**; three host-dependent FUSE tests were ignored by the regular workspace run. `npm ci` and the frontend production build passed, as did all **9 Tauri shell tests**. The final UI-only `desktop-shell/src/main.ts` update (SHA-256 `63ecb12a529e555960fdfbe3b3aeef4e78989dc1d1d626f6e97f76dd763b1e15`) was copied into the isolated source tree and rebuilt successfully.

The exact r2 candidate `outputs/packages/raiun-desktop-linux-account-setup-r2-20261010-x86_64.tar.gz` has SHA-256 `762da325b1e761d0f7c6c4d5de51e71f1ba4318b8b44f36758d48621fd259dea` (manifest timestamp `2026-10-10T08:18:23Z`, commit `2e6df1550e01f0c803aca4e35e1a3a50c390f770`, dirty source tree). It was installed only beneath `/home/raiun-test/account-setup-20261010/isolated-r2/xdg-data`. The archive hash and all four installed payload hashes matched the manifest. Packaged CLI and agent help worked. With fresh synthetic XDG config/state/cache/runtime directories, the packaged agent reported disconnected status with no server or session, then acknowledged shutdown and removed its socket. No live FUSE test was repeated on this UI/profile-default follow-up; the preceding live synthetic FUSE gate remains separate evidence.

No real account, OAuth flow, server, or user data was used. The VM was gracefully shut down after testing. NAS Btrfs corruption counters before, during, and after remained at 63 and 49, with all other listed counters zero. The guest had no graphical session, so this VM run does not verify native account switching, setup wizard, tray, portal, or autostart. A separate safe browser mock preview showed the account selection/header and setup-ready states at 1000×650; it is not native desktop acceptance. Logs are preserved in `outputs/vm-lab/account-setup-20261010` (maintainer-local evidence: `../../outputs/vm-lab/account-setup-20261010/`).

## Tray status and FUSE lookup-cache candidate (10 October 2026)

The isolated source snapshot (`/tmp/raiun-tray-perf-source.tar.gz`, SHA-256 `5acdfea23d1b8463c79e392199cfe702a1770252ec91096a489f3f5e875a1763`) passed workspace formatting and strict Clippy, all **245 workspace tests**, and all **3 separately enabled live synthetic FUSE tests**. Three host-dependent FUSE tests were ignored by the ordinary workspace run. The live tests covered read-only folder-vault browse and open-handle revocation after lock, FUSE roundtrip, and dual-profile mount isolation with exact owned cleanup. The frontend production build passed, and the separate Tauri shell project passed formatting, strict Clippy, and all **10 shell tests**.

The exact candidate `outputs/packages/raiun-desktop-linux-tray-performance-20261010-x86_64.tar.gz` has SHA-256 `c7be1c1bc919a9cd9fbcdf0c980ba047f6bb2e3de6df3408c853b96256e980f4` (manifest timestamp `2026-10-10T08:55:42Z`, commit `2e6df1550e01f0c803aca4e35e1a3a50c390f770`, dirty source tree). It was installed only beneath `/home/raiun-test/tray-perf-20261010/isolated/xdg-data`. The archive hash and all four installed payload hashes matched the manifest. Packaged CLI and agent help worked. With fresh synthetic XDG config/state/cache/runtime directories, the packaged agent reported disconnected status with no server or session, then acknowledged shutdown and removed its socket. No real account, OAuth flow, server, or user data was used.

The guest was gracefully shut down. NAS Btrfs corruption counters before, during, and after remained at 63 and 49, with all other listed counters zero. The VM had no graphical session, so this run does not validate native tray rendering or manual desktop interactions. No laptop application was installed or restarted during this gate. Logs are preserved in `outputs/vm-lab/tray-perf-20261010` (maintainer-local evidence: `../../outputs/vm-lab/tray-perf-20261010/`).

## Encrypted access UI candidate — isolated VM gate (10 October 2026)

The source snapshot `raiun-desktop-source-encrypted-access-20261010.tar.gz`
(SHA-256 `1739138bba2584eef2521731142e370f5dd0ebab7eb61a27512e1be1708778ad`)
passed workspace formatting, strict Clippy, and **253 workspace tests**; four
host-dependent FUSE tests were ignored in the ordinary suite. All four explicit
live synthetic FUSE tests passed: whole-Space browsing, folder-vault browsing
with handle revocation, FUSE roundtrip, and dual-profile mount isolation with
owned cleanup. The frontend install/build passed, as did Tauri shell formatting,
strict Clippy, and all **10 shell tests**.

The exact candidate
`outputs/packages/raiun-desktop-linux-encrypted-access-20261010-x86_64.tar.gz`
has SHA-256
`6881e96edc961b140bf5bed817d1e83fa03a2726915f045b05de0c777c629d08`.
It was installed only beneath a fresh isolated XDG data directory in CachyOS;
the archive hash and all four installed payload hashes matched. Packaged CLI and
agent help worked. Synthetic diagnostics with path/ID canaries and malformed
configuration returned redacted reports. The isolated agent reported
`connected: false`, no server/session, and `paused_space_ids: []`, then shut down
cleanly and removed its control socket. No real account, server, or user data
was used.

No native window was opened, and the encrypted-access interaction was not
verified by clicking through the browser mock: the browser input bridge timed
out on clicks. The frontend production build passed, but native UX acceptance
remains open. The guest was shut down gracefully; NAS Btrfs counters before,
during, and after remained at corruption counts 63 and 49 with all other listed
counters zero. Logs and synthetic outputs are in
`outputs/vm-lab/encrypted-access-20261010` (maintainer-local evidence: `../../outputs/vm-lab/encrypted-access-20261010/`).
