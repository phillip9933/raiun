# Raiun repository layout

Raiun uses one product repository with independent platform projects. Android is present now. Desktop continues separately until a coordinated import; its working files and Git state are not changed by this migration.

```text
raiun/
  .github/workflows/    # Platform CI; GitHub discovers workflows only here
  apps/
    android/           # Complete Gradle project, modules, scripts and docs
  design/              # Shared branding and product design references
  docs/                # Layout and coordinated release guidance
```

The later desktop import belongs in `apps/desktop/`. There is intentionally no placeholder desktop source or build job claiming to validate it today.

## Platform ownership

Open `apps/android` in Android Studio. Run Android commands there; the Gradle root and module names (`:app`, `:core:*`, `:feature:*`) are unchanged. Wrapper, version catalog, scanner lock, analysis config, scripts, schemas, translations and screenshot baselines move together. APKs and test reports are under `apps/android/<module>/build/`.

GitHub workflows stay in `.github/workflows`. Android shell steps use `apps/android` as the working directory. Action inputs, including emulator commands and upload paths, specify it explicitly because they do not inherit shell defaults. Existing workflow filenames and job names are retained for check continuity; branch-protection settings are not changed. Workflows still run for all pull requests and main-branch pushes, avoiding skipped required checks. Introduce platform-aware change selection alongside desktop workflows after reviewing required checks.

Android dependencies resolve independently of Rust, Node or desktop tooling. The scanner remains a checksum-pinned, separately versioned SDK. Branding can share source assets and design references; each app owns native resources and packaging. Add a shared runtime or top-level build system only for a concrete need.

## Compatibility and private files

Source relocation does not change Android's `app.raiun.cloud` application ID, namespace, database schemas, document-provider authorities, credential aliases or signing identity. Build and test from the new path before publishing. Installed-app updates still require the original certificate and an increasing Android version code.

Keep private signing material outside the entire Git repository. Local properties belong in `apps/android/local.properties` and remain ignored. Project caches and outputs stay beside the Android build and never enter desktop source. Never copy credentials or personal test records to make builds portable.

Existing Android history and tags remain at their original revisions and paths. Git can follow renames across the later migration commit; do not rewrite historical tags. The primary checkout and other worktrees may use the previous layout until the migration is integrated.

Maintainer tools outside this repository must point at `apps/android` and its new APK/report paths. Avoid packaging from a preserved older checkout by mistake; verify the selected source, version and artifact before any later signing step.

## Import desktop later

1. Coordinate with desktop work before selecting an exact source revision. Finish or explicitly preserve staged, unstaged and untracked work; never import a live directory or discard local changes.
2. Use a dedicated integration branch/worktree and a reviewed, history-preserving import under `apps/desktop`. Keep the desktop repository and recovery material until acceptance. Copying a source snapshot alone does not merge its history.
3. Retain Cargo/npm locks, per-OS packaging, application identities, credential/storage locations and license attribution. Include desktop privacy, security limits, notices, changelog and verified build instructions. Reconcile imported agent guidance with the new paths and current owner instructions.
4. Move executable desktop workflows into root `.github/workflows` with distinct names. GitHub does not run nested `apps/desktop/.github/workflows`. Update working directories, cache dependency paths, artifacts and per-OS packaging commands. Importing source does not activate signing or publication.
5. Validate actual supported desktop platforms with their existing checks and isolated acceptance procedures. Repeat Android checks for shared changes; an Android pass never establishes desktop compatibility.
6. Review the complete import diff for private data and generated outputs before release acceptance. Source import, publication and package installation are separate actions.

See [Releasing](RELEASING.md) for platform versions and the intended Android 1.0 / desktop 0.7 beta joint launch.
