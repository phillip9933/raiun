# Raiun Desktop

Read ../../AGENTS.md and the root product guidance. This is the desktop app in the Raiun monorepo. Keep app implementation/build/test/docs here and executable GitHub workflows at the repository root. Android is independently owned under ../android; avoid incidental changes there.

Use one Cargo workspace and repository for Linux, Windows, and future macOS. Rust owns the headless engine; UI and OS adapters consume its interfaces. One OS cloud root contains Personal and Spaces. There are no separately registered Space endpoints.

Keep docs/IMPLEMENTATION.md honest: configuration tools are not a working sync agent. Never label transfers complete without verification. Preserve user edits, source, recovery data, and signing material. Tests use synthetic directories and fixtures and never mount, sign in, enable autostart, publish, or delete user data.

The owner requests a parent architect/orchestrator, bounded coding tasks on cheaper subagents, and parent integration and verification. Owner update, 21 October 2026: continue the next Linux and Windows Desktop release at a token-frugal pace. Monitor the account-wide weekly usage window (10080 minutes); stop work and delegated agents when less than 10% remains (usedPercent > 90), and wait for explicit owner resume. This supersedes the earlier credit-balance and rolling-spend rules for this work. Record snapshots outside Git under Raiun outputs/usage-monitor; do not infer per-agent charges.

Owner priority update, 23 October 2026: prioritize bringing Windows to Linux feature parity while continuing focused Linux beta improvements. Use practical beta acceptance, preserve security/account isolation and recovery, and avoid speculative features or exhaustive test expansion. This replaces the earlier Linux-first implementation priority; the weekly usage guard above remains in force.

Run cargo fmt --all --check, cargo clippy --workspace --all-targets --locked -- -D warnings, and cargo test --workspace --locked for Rust changes. Keep Cargo.lock committed. Native adapter code that requires unsafe must live in a separately reviewed crate, not these safe core/configuration crates.


## Sole Desktop coordinator — 31 October 2026

The owner consolidated GUI and CLI ownership in Desktop Client chat
`01a119ad-9089-7a13-87de-562a9031159d`. This checkout is the canonical Desktop
integration source for both entrypoints. The prior CLI-only chat is archived;
its preserved worktree is a handoff reference, not a second active pipeline.
Windows laptop work is bounded platform source/native testing under this chat.
Preserve explicit mode-specific state/credential/registration policies when
sharing code. Use the verified source handoff and ownership plan in the project's
`outputs/desktop-consolidation-20261031/`; run combined checks after composition.
Do not confuse source consolidation with native acceptance or release approval.

## Current release validation scope — owner update, 2 November 2026

The owner explicitly requested removing unnecessary tests from the release
critical path, not merely stopping test expansion. For this release-preparation
phase, use basic build/affected compilation and formatting checks, install/upgrade
and startup/sign-in smoke, one normal file workflow, and essential data-preservation
checks on finished candidates. Do not rerun full workspace suites, the seven-case
R58/R59 acceptance gate, expanded failure matrices or test-protocol preparation as
release requirements. This phase-specific instruction supersedes the earlier
blanket full-workspace rerun instruction. Reuse completed evidence and preserve
existing regression tests and failures. Fix implementation and build the candidates
first. Retain fail-closed encryption, exact account/vault/root binding, conditional
mutations, dirty recovery and safe shutdown; compiled artifacts are not native
acceptance. See docs/COMPLETION-CHECKLIST.md for the same current release boundary.
