# Raiun Desktop

Read ../AGENTS.md and ../../AGENTS.md when available. This is the desktop repository, separate from Raiun Android. Do not modify the Android repository during desktop work.

Use one Cargo workspace and repository for Linux, Windows, and future macOS. Rust owns the headless engine; UI and OS adapters consume its interfaces. One OS cloud root contains Personal and Spaces. There are no separately registered Space endpoints.

Keep docs/IMPLEMENTATION.md honest: configuration tools are not a working sync agent. Never label transfers complete without verification. Preserve user edits, source, recovery data, and signing material. Tests use synthetic directories and fixtures and never mount, sign in, enable autostart, publish, or delete user data.

The owner requests a parent architect/orchestrator, bounded coding tasks on cheaper subagents, and parent integration and verification. Owner update, 17 October 2026: monitor available account-wide credit balances and continue unless the balance drops below 500 credits. This replaces the previous 100-credit rolling-window stop rule for this Desktop work. Below 500, pause all work and agents and wait for explicit owner resume. Store snapshots in ../outputs/usage-monitor/ and do not claim exact agent charges.

Run cargo fmt --all --check, cargo clippy --workspace --all-targets --locked -- -D warnings, and cargo test --workspace --locked for Rust changes. Keep Cargo.lock committed. Native adapter code that requires unsafe must live in a separately reviewed crate, not these safe core/configuration crates.
