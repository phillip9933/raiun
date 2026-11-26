# Tauri single-instance plugin, Raiun Windows scope patch

This directory contains the source, Cargo manifest, README, and license files
from the published `tauri-plugin-single-instance` 2.4.5 crate. The original
crate archive SHA-256 is
`db817fe9295e19b7d8357e900af31edb93703dd9fb6de524b007b47b6afc63b0`.
The source is licensed under Apache-2.0 OR MIT; see the included license files.

Raiun's local changes add `Builder::windows_instance_key`, which appends a
bounded caller-supplied key to the Windows mutex and event-window names only.
The bundle identifier, Linux D-Bus ID, macOS behavior, and default names are
unchanged. A failed Windows mutex creation now returns a setup error.

The shell supplies a scope derived from the current Windows user SID. Keep this
source patch with its exact 2.4.5 manifest and lockfile entry until upstream
offers an equivalent per-user instance key.

The shell excludes this path dependency from its workspace membership. This
retains upstream feature definitions without resolving unused optional features
as workspace-member features; no optional dependency was removed. Runtime notice
collection includes this vendored package and its local provenance file.
