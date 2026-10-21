# Desktop engine language decision

Decision: Rust for the resident desktop engine. Accepted by the owner on 8 October 2026 after comparing Rust with extraction of the existing Android Kotlin code. Confidence is moderate until native provider and resource prototypes pass.

Raiun Desktop is a resident synchronization and filesystem application with a small configuration UI. Its core workload includes arbitrary folder pairs, bidirectional reconciliation, durable transfers, and on-demand file access by other applications. A single OS root contains Personal and Spaces. Linux is first, Windows follows, and macOS must remain practical.

## Why Rust

Rust lets the Linux filesystem adapter and Windows API integration share a native engine without introducing a JVM/native boundary around core filesystem operations. Explicit resource ownership suits a long-lived process with bounded queues, streaming buffers, and caches. Rust is not a guarantee of low memory or sync correctness; those remain design and test responsibilities.

The initial Kotlin proposal overestimated how much of the Android app constituted a reusable desktop engine. The existing folder-backup worker discovers local files and enqueues uploads; it is not a full bidirectional reconciler. Scheduling, document-tree access, and queue ownership depend on Android services. The desktop reconciler, provider, and durable runtime therefore need new implementation in either language.

## The strongest Kotlin case

Android's network module has substantial protocol code, with relatively limited direct Android coupling. Conditional transfer behavior, resume/recovery handling, and rclone-crypt interoperability tests are valuable. A maintained portable Kotlin library could share those implementations between both products. Kotlin/JVM can process large inventories using a disk-backed database and streaming algorithms; no benchmark has shown it incapable of the required scale.

JVM filesystem products exist. [Cryptomator's FUSE adapter](https://github.com/cryptomator/fuse-nio-adapter) and [Cyberduck's core used in Mountain Duck](https://github.com/iterate-ch/cyberduck) are feasibility evidence, not measurements of Raiun's future resource usage. The memory concern alone would not justify a language change.

## Costs we accept

Rust requires porting selected protocol behavior and maintaining another main language alongside Android. Safe Rust does not prevent logical data loss. Native APIs still have platform-specific lifecycle and unsafe boundaries. The Swift macOS extension remains separate. Rust does not automatically deliver installers, correct Cloud Files behavior, or a production filesystem implementation.

Retain protocol fixtures and known-answer crypto vectors, port tests before changing behavior, and compare against an actual supported OpenCloud server. Do not claim the port preserves behavior merely because function names match. Do not copy the Android implementation into a second unmaintained Kotlin fork to avoid making a clear ownership decision.

## Reuse boundaries

| Android source | Desktop treatment |
| --- | --- |
| TransferClient and UploadRecovery | Preserve conditional-write, streaming, ambiguous-outcome and retry semantics through tests |
| LibreGraphSpacesClient and discovery code | Preserve Space identity, permissions and endpoint validation; stream large listings rather than retaining entire DOMs |
| RcloneVaultCipher and crypto tests | Reuse format contracts and independent oracle fixtures; select reviewed Rust primitives and verify interoperability |
| FolderBackupScanWorker and BackupInventory | Reference upload-discovery behavior; implement a new bidirectional baseline/journal model |
| BackupTree | Replace Android document access and whole-tree lists with native incremental inventory |
| WorkManager, Room, Keystore, DocumentsProvider | Replace with desktop scheduling, storage, credentials and native providers |

These references are in the sibling Android checkout under `core/`. No Android source was changed for this decision. Existing crypto integration includes work in progress; fixture coverage must not be described as completed desktop encryption support.

## Validation that can change the design

Prove real Linux filesystem reads/writes, interrupted transfer recovery, bounded enumeration of large directories, one-million-entry inventory behavior, and idle resource usage before significant UI work. Test Windows callbacks early enough to expose binding and lifecycle problems. Prototype macOS extension/engine communication before promising a macOS release.

Reconsider Kotlin if a portable shared core demonstrably removes substantially more work than expected and meets the same resource/integration requirements, or if native Rust dependencies prove unsuitable. Do not switch based on language reputation, a hello-world memory comparison, or sunk scaffolding cost.
