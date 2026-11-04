# Raiun Desktop

Read ../../AGENTS.md and the root product guidance. This is the desktop app in the Raiun monorepo. Keep app implementation/build/test/docs here and executable GitHub workflows at the repository root. Android is independently owned under ../android; avoid incidental changes there.

Use one Cargo workspace and repository for Linux, Windows, and future macOS. Rust owns the headless engine; UI and OS adapters consume its interfaces. One OS cloud root contains Personal and Spaces. There are no separately registered Space endpoints.

Keep docs/IMPLEMENTATION.md honest: configuration tools are not a working sync agent. Never label transfers complete without verification. Preserve user edits, source, recovery data, and signing material. Tests use synthetic directories and fixtures and never mount, sign in, enable autostart, publish, or delete user data.

Run cargo fmt --all --check, cargo clippy --workspace --all-targets --locked -- -D warnings, and cargo test --workspace --locked for Rust changes. Keep Cargo.lock committed. Native adapter code that requires unsafe must live in a separately reviewed crate, not these safe core/configuration crates.

## Integration and release scope

Keep GUI and CLI development in the same coordinated integration source while preserving mode-specific state, credential and registration policies. Keep independent development worktrees and Windows testing data intact. Source consolidation is not native acceptance or publication approval.

Follow the currently authorized validation scope. Record what ran against the exact candidate and what evidence was reused; compiled artifacts are not native acceptance. Preserve fail-closed encryption, exact account/vault/root binding, conditional mutations, dirty recovery and safe shutdown. Temporary owner usage limits, chat identifiers and release exceptions belong in private project guidance.
