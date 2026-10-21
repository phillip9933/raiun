# Desktop third-party notices

This inventory accompanies the Linux x86_64 beta. Third-party copyrights and licenses remain with their respective holders. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for Raiun first-party terms.

## Scope and retained texts

The offline collector traverses the two locked Linux Cargo graphs from the shipped agent, CLI and Tauri shell, excluding dev-only edges and conservatively retaining build/proc-macro dependencies. It records 455 distinct crate versions and the two production UI packages. This is a source/notice inventory, not a claim that every listed crate is linked into every binary. Development npm build tools are outside the shipped UI runtime inventory.

Exact lock hashes, declared license expressions, source repositories and retained text hashes are in [legal/dependency-inventory.json](legal/dependency-inventory.json). All available cached nested LICENSE/COPYING/NOTICE/COPYRIGHT files are retained. Upstream declarations with `/` are reproduced verbatim rather than silently normalized. Retaining alternative license texts does not replace combined-license requirements.

Supplemental cached Vite, Rollup, esbuild and TypeScript build-tool notices are recorded separately in the inventory and `legal/build-tools/`. Vite can emit its preload helper into the production bundle; retaining these notices does not claim every build tool is distributed.

Rust standard-library copyright material is retained in [legal/rust-toolchain/COPYRIGHT-library.html](legal/rust-toolchain/COPYRIGHT-library.html), with locally installed toolchain license texts. The existing [EME MIT notice](crates/raiun-vault/EME-MIT-LICENSE) is retained verbatim and copied into `legal/`.

The production npm dialog package ships an SPDX attribution record; the inventory also references full MIT/Apache texts from the same cached versioned upstream Rust plugin. Those supplemental texts are identified separately, not presented as files shipped by npm.

System GTK/WebKitGTK, Ayatana AppIndicator, FUSE, Secret Service, Zenity and their distribution dependencies are prerequisites supplied by the OS, not copied into this inventory by the collector. Any future bundled library requires its own notice/source review.

## Source availability

Raiun corresponding source and build scripts are available at https://github.com/phillip9933/raiun under `apps/desktop`. Match the release tag and packaged source revision. Locked external crate source is available as exact versioned crates.io packages; links for MPL-2.0 components are listed below. These dependencies retain their upstream terms; no local modifications to cached external crate sources were made for this collection.

- cssparser 0.36.0: https://crates.io/api/v1/crates/cssparser/0.36.0/download
- cssparser-macros 0.6.1: https://crates.io/api/v1/crates/cssparser-macros/0.6.1/download
- dtoa-short 0.3.5: https://crates.io/api/v1/crates/dtoa-short/0.3.5/download
- option-ext 0.2.0: https://crates.io/api/v1/crates/option-ext/0.2.0/download
- selectors 0.36.1: https://crates.io/api/v1/crates/selectors/0.36.1/download

## Exact upstream supplements for cached-notice gaps

Eleven cached crate distributions omitted standalone license or attribution files.
Those text gaps are now supplemented from the exact upstream commits recorded
inside their registry archives. Each cached `.crate` SHA-256 was verified against
`Cargo.lock` before its VCS metadata was trusted. The full record, retrieval URLs,
source archive checksums and retained-text hashes are in
[legal/upstream-notice-provenance.json](legal/upstream-notice-provenance.json).

- `alloc-stdlib 0.2.4`: exact-commit Dropbox BSD-3-Clause notice.
- `dlopen2 0.8.2` and `dlopen2_derive 0.4.3`: exact-commit MIT license with original author attributions.
- `libappindicator-sys 0.9.0`: exact-commit MIT/Apache texts; upstream `sys/Cargo.toml` is byte-identical to the verified crate's original manifest, establishing the repository join absent from its package metadata.
- Five UNIC `0.9.0` crates: MIT/Apache texts plus `COPYRIGHT.md` and `AUTHORS` from their respective exact commits.
- `tauri-plugin 2.6.3`: MIT/Apache texts from the recorded Tauri commit.
- `selectors 0.36.1`: its exact registry source license header and original manifest are retained, together with the official Mozilla MPL-2.0 text referenced by that header. The exact upstream repository root contains no standalone LICENSE file. This is recorded as a source-header/official-text resolution, not a fabricated upstream file.

No previously identified text gap remains unresolved after this bounded primary-source retrieval. This is not a comprehensive legal certification or a binary-link audit. Parent release integration must retain these materials and corresponding source availability. The collector remains offline: it rechecks archive checksums, recorded commits and retained text hashes without downloading new material.

## Production UI packages

| Package | Version | Declared license | Retained text |
| --- | --- | --- | --- |
| @tauri-apps/api | 2.11.1 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/npm/@tauri-apps__api-2.11.1/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/npm/@tauri-apps__api-2.11.1/LICENSE_MIT) |
| @tauri-apps/plugin-dialog | 2.7.3 | MIT OR Apache-2.0 | [LICENSE.spdx](legal/npm/@tauri-apps__plugin-dialog-2.7.3/LICENSE.spdx) |

## Locked Linux Rust dependency inventory

| Crate | Version | Declared license | Retained texts |
| --- | --- | --- | --- |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | [LICENSE-0BSD](legal/rust/adler2-2.0.1/LICENSE-0BSD), [LICENSE-APACHE](legal/rust/adler2-2.0.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/adler2-2.0.1/LICENSE-MIT) |
| aead | 0.5.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/aead-0.5.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/aead-0.5.2/LICENSE-MIT) |
| aes | 0.8.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/aes-0.8.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/aes-0.8.4/LICENSE-MIT) |
| ahash | 0.8.12 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ahash-0.8.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ahash-0.8.12/LICENSE-MIT) |
| aho-corasick | 1.1.5 | Unlicense OR MIT | [COPYING](legal/rust/aho-corasick-1.1.5/COPYING), [LICENSE-MIT](legal/rust/aho-corasick-1.1.5/LICENSE-MIT) |
| alloc-no-stdlib | 2.0.4 | BSD-3-Clause | [LICENSE](legal/rust/alloc-no-stdlib-2.0.4/LICENSE) |
| alloc-stdlib | 0.2.4 | BSD-3-Clause | [LICENSE](legal/upstream-retrieval/alloc-ae42d22078b98549e987d2f03d12df7b984fde47/LICENSE) |
| ambient-authority | 0.0.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/ambient-authority-0.0.2/COPYRIGHT), [LICENSE-APACHE](legal/rust/ambient-authority-0.0.2/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/ambient-authority-0.0.2/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/ambient-authority-0.0.2/LICENSE-MIT) |
| anstream | 1.0.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/anstream-1.0.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/anstream-1.0.0/LICENSE-MIT) |
| anstyle | 1.0.14 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/anstyle-1.0.14/LICENSE-APACHE), [LICENSE-MIT](legal/rust/anstyle-1.0.14/LICENSE-MIT) |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/anstyle-parse-1.0.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/anstyle-parse-1.0.0/LICENSE-MIT) |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/anstyle-query-1.1.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/anstyle-query-1.1.5/LICENSE-MIT) |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/anyhow-1.0.104/LICENSE-APACHE), [LICENSE-MIT](legal/rust/anyhow-1.0.104/LICENSE-MIT) |
| ashpd | 0.11.1 | MIT | [LICENSE](legal/rust/ashpd-0.11.1/LICENSE) |
| async-broadcast | 0.7.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/async-broadcast-0.7.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-broadcast-0.7.2/LICENSE-MIT) |
| async-channel | 2.5.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-channel-2.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-channel-2.5.0/LICENSE-MIT) |
| async-executor | 1.14.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-executor-1.14.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-executor-1.14.0/LICENSE-MIT) |
| async-io | 2.6.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-io-2.6.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-io-2.6.0/LICENSE-MIT) |
| async-lock | 3.4.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-lock-3.4.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-lock-3.4.2/LICENSE-MIT) |
| async-process | 2.5.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-process-2.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-process-2.5.0/LICENSE-MIT) |
| async-signal | 0.2.14 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-signal-0.2.14/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-signal-0.2.14/LICENSE-MIT) |
| async-task | 4.7.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/async-task-4.7.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-task-4.7.1/LICENSE-MIT) |
| async-trait | 0.1.92 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/async-trait-0.1.92/LICENSE-APACHE), [LICENSE-MIT](legal/rust/async-trait-0.1.92/LICENSE-MIT) |
| atk | 0.18.2 | MIT | [COPYRIGHT](legal/rust/atk-0.18.2/COPYRIGHT), [LICENSE](legal/rust/atk-0.18.2/LICENSE) |
| atk-sys | 0.18.2 | MIT | [LICENSE](legal/rust/atk-sys-0.18.2/LICENSE) |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/atomic-waker-1.1.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/atomic-waker-1.1.2/LICENSE-MIT), [LICENSE-THIRD-PARTY](legal/rust/atomic-waker-1.1.2/LICENSE-THIRD-PARTY) |
| autocfg | 1.5.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/autocfg-1.5.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/autocfg-1.5.1/LICENSE-MIT) |
| base64 | 0.22.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/base64-0.22.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/base64-0.22.1/LICENSE-MIT) |
| base64 | 0.23.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/base64-0.23.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/base64-0.23.1/LICENSE-MIT) |
| base64ct | 1.8.3 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/base64ct-1.8.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/base64ct-1.8.3/LICENSE-MIT) |
| bit-set | 0.8.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/bit-set-0.8.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/bit-set-0.8.0/LICENSE-MIT) |
| bit-vec | 0.8.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/bit-vec-0.8.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/bit-vec-0.8.0/LICENSE-MIT) |
| bitflags | 1.3.2 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/bitflags-1.3.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/bitflags-1.3.2/LICENSE-MIT) |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/bitflags-2.13.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/bitflags-2.13.2/LICENSE-MIT) |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/block-buffer-0.10.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/block-buffer-0.10.4/LICENSE-MIT) |
| blocking | 1.7.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/blocking-1.7.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/blocking-1.7.0/LICENSE-MIT) |
| brotli | 8.0.4 | BSD-3-Clause AND MIT | [LICENSE.BSD-3-Clause](legal/rust/brotli-8.0.4/LICENSE.BSD-3-Clause), [LICENSE.MIT](legal/rust/brotli-8.0.4/LICENSE.MIT) |
| brotli-decompressor | 5.0.3 | BSD-3-Clause/MIT | [LICENSE](legal/rust/brotli-decompressor-5.0.3/LICENSE) |
| byteorder | 1.5.0 | Unlicense OR MIT | [COPYING](legal/rust/byteorder-1.5.0/COPYING), [LICENSE-MIT](legal/rust/byteorder-1.5.0/LICENSE-MIT) |
| bytes | 1.12.1 | MIT | [LICENSE](legal/rust/bytes-1.12.1/LICENSE) |
| cairo-rs | 0.18.5 | MIT | [COPYRIGHT](legal/rust/cairo-rs-0.18.5/COPYRIGHT), [LICENSE](legal/rust/cairo-rs-0.18.5/LICENSE) |
| cairo-sys-rs | 0.18.2 | MIT | [LICENSE](legal/rust/cairo-sys-rs-0.18.2/LICENSE) |
| camino | 1.2.6 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/camino-1.2.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/camino-1.2.6/LICENSE-MIT) |
| cap-fs-ext | 4.0.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/cap-fs-ext-4.0.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/cap-fs-ext-4.0.3/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/cap-fs-ext-4.0.3/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/cap-fs-ext-4.0.3/LICENSE-MIT) |
| cap-primitives | 4.0.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/cap-primitives-4.0.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/cap-primitives-4.0.3/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/cap-primitives-4.0.3/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/cap-primitives-4.0.3/LICENSE-MIT) |
| cap-std | 4.0.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/cap-std-4.0.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/cap-std-4.0.3/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/cap-std-4.0.3/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/cap-std-4.0.3/LICENSE-MIT) |
| cargo-platform | 0.1.9 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cargo-platform-0.1.9/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cargo-platform-0.1.9/LICENSE-MIT) |
| cargo_metadata | 0.19.2 | MIT | [LICENSE-MIT](legal/rust/cargo_metadata-0.19.2/LICENSE-MIT) |
| cargo_toml | 0.22.3 | Apache-2.0 OR MIT | [LICENSE](legal/rust/cargo_toml-0.22.3/LICENSE) |
| caseless | 0.2.2 | MIT | [LICENSE](legal/rust/caseless-0.2.2/LICENSE) |
| cc | 1.6.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cc-1.6.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cc-1.6.0/LICENSE-MIT) |
| cfb | 0.7.3 | MIT | [LICENSE](legal/rust/cfb-0.7.3/LICENSE) |
| cfg-expr | 0.15.8 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cfg-expr-0.15.8/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cfg-expr-0.15.8/LICENSE-MIT) |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cfg-if-1.0.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cfg-if-1.0.5/LICENSE-MIT) |
| cfg_aliases | 0.2.2 | MIT | [LICENSE](legal/rust/cfg_aliases-0.2.2/LICENSE) |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/chacha20-0.10.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/chacha20-0.10.2/LICENSE-MIT) |
| chrono | 0.4.45 | MIT OR Apache-2.0 | [LICENSE.txt](legal/rust/chrono-0.4.45/LICENSE.txt) |
| cipher | 0.4.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cipher-0.4.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cipher-0.4.4/LICENSE-MIT) |
| clap | 4.6.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/clap-4.6.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/clap-4.6.7/LICENSE-MIT) |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/clap_builder-4.6.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/clap_builder-4.6.7/LICENSE-MIT) |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/clap_derive-4.6.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/clap_derive-4.6.7/LICENSE-MIT) |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/clap_lex-1.1.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/clap_lex-1.1.1/LICENSE-MIT) |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/colorchoice-1.0.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/colorchoice-1.0.5/LICENSE-MIT) |
| concurrent-queue | 2.5.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/concurrent-queue-2.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/concurrent-queue-2.5.0/LICENSE-MIT) |
| cookie | 0.18.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cookie-0.18.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cookie-0.18.2/LICENSE-MIT) |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cpufeatures-0.2.17/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cpufeatures-0.2.17/LICENSE-MIT) |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/cpufeatures-0.3.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/cpufeatures-0.3.1/LICENSE-MIT) |
| crc32fast | 1.5.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/crc32fast-1.5.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/crc32fast-1.5.2/LICENSE-MIT) |
| crossbeam-channel | 0.5.17 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/crossbeam-channel-0.5.17/LICENSE-APACHE), [LICENSE-MIT](legal/rust/crossbeam-channel-0.5.17/LICENSE-MIT), [LICENSE-THIRD-PARTY](legal/rust/crossbeam-channel-0.5.17/LICENSE-THIRD-PARTY) |
| crossbeam-utils | 0.8.23 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/crossbeam-utils-0.8.23/LICENSE-APACHE), [LICENSE-MIT](legal/rust/crossbeam-utils-0.8.23/LICENSE-MIT) |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/crypto-common-0.1.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/crypto-common-0.1.7/LICENSE-MIT) |
| crypto_secretbox | 0.1.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/crypto_secretbox-0.1.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/crypto_secretbox-0.1.1/LICENSE-MIT) |
| cssparser | 0.36.0 | MPL-2.0 | [LICENSE](legal/rust/cssparser-0.36.0/LICENSE) |
| cssparser-macros | 0.6.1 | MPL-2.0 | [LICENSE](legal/rust/cssparser-macros-0.6.1/LICENSE) |
| ctor | 0.8.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/ctor-0.8.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ctor-0.8.0/LICENSE-MIT) |
| ctor-proc-macro | 0.0.7 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/ctor-proc-macro-0.0.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ctor-proc-macro-0.0.7/LICENSE-MIT) |
| ctrlc | 3.5.2 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/ctrlc-3.5.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ctrlc-3.5.2/LICENSE-MIT) |
| darling | 0.21.3 | MIT | [LICENSE](legal/rust/darling-0.21.3/LICENSE) |
| darling_core | 0.21.3 | MIT | [LICENSE](legal/rust/darling_core-0.21.3/LICENSE) |
| darling_macro | 0.21.3 | MIT | [LICENSE](legal/rust/darling_macro-0.21.3/LICENSE) |
| dbus | 0.9.12 | Apache-2.0/MIT | [LICENSE-APACHE](legal/rust/dbus-0.9.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dbus-0.9.12/LICENSE-MIT) |
| deranged | 0.5.8 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/deranged-0.5.8/LICENSE-Apache), [LICENSE-MIT](legal/rust/deranged-0.5.8/LICENSE-MIT) |
| derive_more | 2.1.1 | MIT | [LICENSE](legal/rust/derive_more-2.1.1/LICENSE) |
| derive_more-impl | 2.1.1 | MIT | [LICENSE](legal/rust/derive_more-impl-2.1.1/LICENSE) |
| digest | 0.10.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/digest-0.10.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/digest-0.10.7/LICENSE-MIT) |
| dirs | 6.0.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/dirs-6.0.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dirs-6.0.0/LICENSE-MIT) |
| dirs-sys | 0.5.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/dirs-sys-0.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dirs-sys-0.5.0/LICENSE-MIT) |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/displaydoc-0.2.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/displaydoc-0.2.7/LICENSE-MIT) |
| dlib | 0.5.3 | MIT | [LICENSE.txt](legal/rust/dlib-0.5.3/LICENSE.txt) |
| dlopen2 | 0.8.2 | MIT | [LICENSE](legal/upstream-retrieval/dlopen-cc80e4a0a90d499b677fdf7743699b4b3a43a989/LICENSE) |
| dlopen2_derive | 0.4.3 | MIT | [LICENSE](legal/upstream-retrieval/dlopen-cc80e4a0a90d499b677fdf7743699b4b3a43a989/LICENSE) |
| dom_query | 0.27.0 | MIT | [LICENSE](legal/rust/dom_query-0.27.0/LICENSE) |
| downcast-rs | 1.2.1 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/downcast-rs-1.2.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/downcast-rs-1.2.1/LICENSE-MIT) |
| dpi | 0.1.2 | Apache-2.0 AND MIT | [LICENSE](legal/rust/dpi-0.1.2/LICENSE), [LICENSE-LIBM-MIT](legal/rust/dpi-0.1.2/LICENSE-LIBM-MIT) |
| dtoa | 1.0.11 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/dtoa-1.0.11/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dtoa-1.0.11/LICENSE-MIT) |
| dtoa-short | 0.3.5 | MPL-2.0 | [LICENSE](legal/rust/dtoa-short-0.3.5/LICENSE) |
| dtor | 0.3.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/dtor-0.3.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dtor-0.3.0/LICENSE-MIT) |
| dtor-proc-macro | 0.0.6 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/dtor-proc-macro-0.0.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dtor-proc-macro-0.0.6/LICENSE-MIT) |
| dunce | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 | [LICENSE](legal/rust/dunce-1.0.5/LICENSE) |
| dyn-clone | 1.0.20 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/dyn-clone-1.0.20/LICENSE-APACHE), [LICENSE-MIT](legal/rust/dyn-clone-1.0.20/LICENSE-MIT) |
| embed-resource | 3.0.12 | MIT | [LICENSE](legal/rust/embed-resource-3.0.12/LICENSE) |
| endi | 1.1.1 | MIT | [LICENSE-MIT](legal/rust/endi-1.1.1/LICENSE-MIT) |
| enumflags2 | 0.7.12 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/enumflags2-0.7.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/enumflags2-0.7.12/LICENSE-MIT) |
| enumflags2_derive | 0.7.12 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/enumflags2_derive-0.7.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/enumflags2_derive-0.7.12/LICENSE-MIT) |
| equivalent | 1.0.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/equivalent-1.0.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/equivalent-1.0.2/LICENSE-MIT) |
| erased-serde | 0.4.10 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/erased-serde-0.4.10/LICENSE-APACHE), [LICENSE-MIT](legal/rust/erased-serde-0.4.10/LICENSE-MIT) |
| errno | 0.3.14 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/errno-0.3.14/LICENSE-APACHE), [LICENSE-MIT](legal/rust/errno-0.3.14/LICENSE-MIT) |
| event-listener | 5.4.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/event-listener-5.4.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/event-listener-5.4.2/LICENSE-MIT) |
| event-listener-strategy | 0.5.4 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/event-listener-strategy-0.5.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/event-listener-strategy-0.5.4/LICENSE-MIT) |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/fallible-iterator-0.3.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fallible-iterator-0.3.0/LICENSE-MIT) |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/fallible-streaming-iterator-0.1.9/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fallible-streaming-iterator-0.1.9/LICENSE-MIT) |
| fastrand | 2.5.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/fastrand-2.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fastrand-2.5.0/LICENSE-MIT) |
| fdeflate | 0.3.7 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/fdeflate-0.3.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fdeflate-0.3.7/LICENSE-MIT) |
| field-offset | 0.3.6 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/field-offset-0.3.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/field-offset-0.3.6/LICENSE-MIT) |
| find-msvc-tools | 0.1.14 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/find-msvc-tools-0.1.14/LICENSE-APACHE), [LICENSE-MIT](legal/rust/find-msvc-tools-0.1.14/LICENSE-MIT) |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/flate2-1.1.10/LICENSE-APACHE), [LICENSE-MIT](legal/rust/flate2-1.1.10/LICENSE-MIT) |
| fnv | 1.0.7 | Apache-2.0 / MIT | [LICENSE-APACHE](legal/rust/fnv-1.0.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fnv-1.0.7/LICENSE-MIT) |
| foldhash | 0.2.0 | Zlib | [LICENSE](legal/rust/foldhash-0.2.0/LICENSE) |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/form_urlencoded-1.2.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/form_urlencoded-1.2.2/LICENSE-MIT) |
| fs-set-times | 0.20.3 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/fs-set-times-0.20.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/fs-set-times-0.20.3/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/fs-set-times-0.20.3/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/fs-set-times-0.20.3/LICENSE-MIT) |
| fs2 | 0.4.3 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/fs2-0.4.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/fs2-0.4.3/LICENSE-MIT) |
| fuser | 0.18.0 | MIT | [LICENSE.md](legal/rust/fuser-0.18.0/LICENSE.md) |
| futures-channel | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-channel-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-channel-0.3.34/LICENSE-MIT) |
| futures-core | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-core-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-core-0.3.34/LICENSE-MIT) |
| futures-executor | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-executor-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-executor-0.3.34/LICENSE-MIT) |
| futures-io | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-io-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-io-0.3.34/LICENSE-MIT) |
| futures-lite | 2.6.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/futures-lite-2.6.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-lite-2.6.1/LICENSE-MIT), [LICENSE-THIRD-PARTY](legal/rust/futures-lite-2.6.1/LICENSE-THIRD-PARTY) |
| futures-macro | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-macro-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-macro-0.3.34/LICENSE-MIT) |
| futures-sink | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-sink-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-sink-0.3.34/LICENSE-MIT) |
| futures-task | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-task-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-task-0.3.34/LICENSE-MIT) |
| futures-util | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/futures-util-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/futures-util-0.3.34/LICENSE-MIT) |
| gdk | 0.18.2 | MIT | [COPYRIGHT](legal/rust/gdk-0.18.2/COPYRIGHT), [LICENSE](legal/rust/gdk-0.18.2/LICENSE) |
| gdk-pixbuf | 0.18.5 | MIT | [COPYRIGHT](legal/rust/gdk-pixbuf-0.18.5/COPYRIGHT), [LICENSE](legal/rust/gdk-pixbuf-0.18.5/LICENSE) |
| gdk-pixbuf-sys | 0.18.0 | MIT | [LICENSE](legal/rust/gdk-pixbuf-sys-0.18.0/LICENSE) |
| gdk-sys | 0.18.2 | MIT | [LICENSE](legal/rust/gdk-sys-0.18.2/LICENSE) |
| gdkwayland-sys | 0.18.2 | MIT | [LICENSE](legal/rust/gdkwayland-sys-0.18.2/LICENSE) |
| gdkx11 | 0.18.2 | MIT | [COPYRIGHT](legal/rust/gdkx11-0.18.2/COPYRIGHT), [LICENSE](legal/rust/gdkx11-0.18.2/LICENSE) |
| gdkx11-sys | 0.18.2 | MIT | [LICENSE](legal/rust/gdkx11-sys-0.18.2/LICENSE) |
| generic-array | 0.14.7 | MIT | [LICENSE](legal/rust/generic-array-0.14.7/LICENSE) |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/getrandom-0.2.17/LICENSE-APACHE), [LICENSE-MIT](legal/rust/getrandom-0.2.17/LICENSE-MIT) |
| getrandom | 0.3.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/getrandom-0.3.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/getrandom-0.3.4/LICENSE-MIT) |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/getrandom-0.4.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/getrandom-0.4.3/LICENSE-MIT) |
| gio | 0.18.4 | MIT | [COPYRIGHT](legal/rust/gio-0.18.4/COPYRIGHT), [LICENSE](legal/rust/gio-0.18.4/LICENSE) |
| gio-sys | 0.18.1 | MIT | [LICENSE](legal/rust/gio-sys-0.18.1/LICENSE) |
| glib | 0.18.5 | MIT | [COPYRIGHT](legal/rust/glib-0.18.5/COPYRIGHT), [LICENSE](legal/rust/glib-0.18.5/LICENSE) |
| glib-macros | 0.18.5 | MIT | [COPYRIGHT](legal/rust/glib-macros-0.18.5/COPYRIGHT), [LICENSE](legal/rust/glib-macros-0.18.5/LICENSE) |
| glib-sys | 0.18.1 | MIT | [LICENSE](legal/rust/glib-sys-0.18.1/LICENSE) |
| glob | 0.3.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/glob-0.3.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/glob-0.3.4/LICENSE-MIT) |
| gobject-sys | 0.18.0 | MIT | [LICENSE](legal/rust/gobject-sys-0.18.0/LICENSE) |
| gtk | 0.18.2 | MIT | [COPYRIGHT](legal/rust/gtk-0.18.2/COPYRIGHT), [LICENSE](legal/rust/gtk-0.18.2/LICENSE) |
| gtk-sys | 0.18.2 | MIT | [LICENSE](legal/rust/gtk-sys-0.18.2/LICENSE) |
| gtk3-macros | 0.18.2 | MIT | [COPYRIGHT](legal/rust/gtk3-macros-0.18.2/COPYRIGHT), [LICENSE](legal/rust/gtk3-macros-0.18.2/LICENSE) |
| hashbrown | 0.12.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hashbrown-0.12.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hashbrown-0.12.3/LICENSE-MIT) |
| hashbrown | 0.14.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hashbrown-0.14.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hashbrown-0.14.5/LICENSE-MIT) |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hashbrown-0.17.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hashbrown-0.17.1/LICENSE-MIT) |
| hashlink | 0.9.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hashlink-0.9.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hashlink-0.9.1/LICENSE-MIT) |
| heck | 0.4.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/heck-0.4.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/heck-0.4.1/LICENSE-MIT) |
| heck | 0.5.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/heck-0.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/heck-0.5.0/LICENSE-MIT) |
| hex | 0.4.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hex-0.4.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hex-0.4.3/LICENSE-MIT) |
| hmac | 0.12.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/hmac-0.12.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/hmac-0.12.1/LICENSE-MIT) |
| html5ever | 0.38.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/html5ever-0.38.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/html5ever-0.38.0/LICENSE-MIT) |
| http | 1.5.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/http-1.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/http-1.5.0/LICENSE-MIT) |
| http-body | 1.1.0 | MIT | [LICENSE](legal/rust/http-body-1.1.0/LICENSE) |
| http-body-util | 0.1.5 | MIT | [LICENSE](legal/rust/http-body-util-0.1.5/LICENSE) |
| httparse | 1.10.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/httparse-1.10.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/httparse-1.10.1/LICENSE-MIT) |
| hyper | 1.12.0 | MIT | [LICENSE](legal/rust/hyper-1.12.0/LICENSE) |
| hyper-rustls | 0.27.10 | Apache-2.0 OR ISC OR MIT | [LICENSE-APACHE](legal/rust/hyper-rustls-0.27.10/LICENSE-APACHE), [LICENSE-ISC](legal/rust/hyper-rustls-0.27.10/LICENSE-ISC), [LICENSE-MIT](legal/rust/hyper-rustls-0.27.10/LICENSE-MIT) |
| hyper-util | 0.1.21 | MIT | [LICENSE](legal/rust/hyper-util-0.1.21/LICENSE) |
| iana-time-zone | 0.1.65 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/iana-time-zone-0.1.65/LICENSE-APACHE), [LICENSE-MIT](legal/rust/iana-time-zone-0.1.65/LICENSE-MIT) |
| ico | 0.5.0 | MIT | [LICENSE](legal/rust/ico-0.5.0/LICENSE) |
| icu_collections | 2.1.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_collections-2.1.1/LICENSE) |
| icu_collections | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_collections-2.3.0/LICENSE) |
| icu_locale_core | 2.1.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_locale_core-2.1.1/LICENSE) |
| icu_locale_core | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_locale_core-2.3.0/LICENSE) |
| icu_normalizer | 2.1.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_normalizer-2.1.1/LICENSE) |
| icu_normalizer | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_normalizer-2.3.0/LICENSE) |
| icu_normalizer_data | 2.1.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_normalizer_data-2.1.1/LICENSE) |
| icu_normalizer_data | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_normalizer_data-2.3.0/LICENSE) |
| icu_properties | 2.1.2 | Unicode-3.0 | [LICENSE](legal/rust/icu_properties-2.1.2/LICENSE) |
| icu_properties | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_properties-2.3.0/LICENSE) |
| icu_properties_data | 2.1.2 | Unicode-3.0 | [LICENSE](legal/rust/icu_properties_data-2.1.2/LICENSE) |
| icu_properties_data | 2.3.0 | Unicode-3.0 | [LICENSE](legal/rust/icu_properties_data-2.3.0/LICENSE) |
| icu_provider | 2.1.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_provider-2.1.1/LICENSE) |
| icu_provider | 2.3.1 | Unicode-3.0 | [LICENSE](legal/rust/icu_provider-2.3.1/LICENSE) |
| ident_case | 1.0.1 | MIT/Apache-2.0 | [LICENSE](legal/rust/ident_case-1.0.1/LICENSE) |
| idna | 1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/idna-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/idna-1.1.0/LICENSE-MIT) |
| idna_adapter | 1.2.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/idna_adapter-1.2.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/idna_adapter-1.2.1/LICENSE-MIT) |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/idna_adapter-1.2.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/idna_adapter-1.2.2/LICENSE-MIT) |
| indexmap | 1.9.3 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/indexmap-1.9.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/indexmap-1.9.3/LICENSE-MIT) |
| indexmap | 2.14.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/indexmap-2.14.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/indexmap-2.14.2/LICENSE-MIT) |
| infer | 0.19.0 | MIT | [LICENSE](legal/rust/infer-0.19.0/LICENSE) |
| inout | 0.1.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/inout-0.1.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/inout-0.1.4/LICENSE-MIT) |
| io-extras | 0.19.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/io-extras-0.19.0/COPYRIGHT), [LICENSE-APACHE](legal/rust/io-extras-0.19.0/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/io-extras-0.19.0/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/io-extras-0.19.0/LICENSE-MIT) |
| io-lifetimes | 2.0.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/io-lifetimes-2.0.4/COPYRIGHT), [LICENSE-APACHE](legal/rust/io-lifetimes-2.0.4/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/io-lifetimes-2.0.4/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/io-lifetimes-2.0.4/LICENSE-MIT) |
| io-lifetimes | 3.0.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/io-lifetimes-3.0.1/COPYRIGHT), [LICENSE-APACHE](legal/rust/io-lifetimes-3.0.1/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/io-lifetimes-3.0.1/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/io-lifetimes-3.0.1/LICENSE-MIT) |
| ipnet | 2.12.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ipnet-2.12.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ipnet-2.12.2/LICENSE-MIT) |
| is-docker | 0.2.0 | MIT | [LICENSE](legal/rust/is-docker-0.2.0/LICENSE) |
| is-wsl | 0.4.0 | MIT | [LICENSE](legal/rust/is-wsl-0.4.0/LICENSE) |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/is_terminal_polyfill-1.70.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/is_terminal_polyfill-1.70.2/LICENSE-MIT) |
| itoa | 1.0.18 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/itoa-1.0.18/LICENSE-APACHE), [LICENSE-MIT](legal/rust/itoa-1.0.18/LICENSE-MIT) |
| javascriptcore-rs | 1.1.2 | MIT | [LICENSE](legal/rust/javascriptcore-rs-1.1.2/LICENSE) |
| javascriptcore-rs-sys | 1.1.1 | MIT | [LICENSE](legal/rust/javascriptcore-rs-sys-1.1.1/LICENSE) |
| json-patch | 3.0.1 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/json-patch-3.0.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/json-patch-3.0.1/LICENSE-MIT) |
| jsonptr | 0.6.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/jsonptr-0.6.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/jsonptr-0.6.3/LICENSE-MIT) |
| keyboard-types | 0.7.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/keyboard-types-0.7.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/keyboard-types-0.7.0/LICENSE-MIT) |
| libappindicator | 0.9.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/libappindicator-0.9.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/libappindicator-0.9.0/LICENSE-MIT) |
| libappindicator-sys | 0.9.0 | Apache-2.0 OR MIT | [LICENSE-MIT](legal/upstream-retrieval/indicator-eafd1e3682a1247f595410266091e9684021cb6f/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/indicator-eafd1e3682a1247f595410266091e9684021cb6f/LICENSE-APACHE) |
| libc | 0.2.190 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/libc-0.2.190/LICENSE-APACHE), [LICENSE-MIT](legal/rust/libc-0.2.190/LICENSE-MIT) |
| libdbus-sys | 0.2.7 | Apache-2.0/MIT | [LICENSE-APACHE](legal/rust/libdbus-sys-0.2.7/LICENSE-APACHE), [LICENSE-MIT](legal/rust/libdbus-sys-0.2.7/LICENSE-MIT), [COPYING](legal/rust/libdbus-sys-0.2.7/vendor/dbus/COPYING), [COPYING-CMAKE-SCRIPTS](legal/rust/libdbus-sys-0.2.7/vendor/dbus/cmake/modules/COPYING-CMAKE-SCRIPTS) |
| libloading | 0.7.4 | ISC | [LICENSE](legal/rust/libloading-0.7.4/LICENSE) |
| libsqlite3-sys | 0.30.1 | MIT | [LICENSE](legal/rust/libsqlite3-sys-0.30.1/LICENSE), [LICENSE](legal/rust/libsqlite3-sys-0.30.1/sqlcipher/LICENSE) |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/linux-raw-sys-0.12.1/COPYRIGHT), [LICENSE-APACHE](legal/rust/linux-raw-sys-0.12.1/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/linux-raw-sys-0.12.1/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/linux-raw-sys-0.12.1/LICENSE-MIT) |
| litemap | 0.8.3 | Unicode-3.0 | [LICENSE](legal/rust/litemap-0.8.3/LICENSE) |
| lock_api | 0.4.14 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/lock_api-0.4.14/LICENSE-APACHE), [LICENSE-MIT](legal/rust/lock_api-0.4.14/LICENSE-MIT) |
| log | 0.4.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/log-0.4.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/log-0.4.34/LICENSE-MIT) |
| lru-slab | 0.1.3 | MIT OR Apache-2.0 OR Zlib | [LICENSE-APACHE](legal/rust/lru-slab-0.1.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/lru-slab-0.1.3/LICENSE-MIT), [LICENSE-ZLIB](legal/rust/lru-slab-0.1.3/LICENSE-ZLIB) |
| markup5ever | 0.38.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/markup5ever-0.38.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/markup5ever-0.38.0/LICENSE-MIT) |
| maybe-owned | 0.3.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/maybe-owned-0.3.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/maybe-owned-0.3.4/LICENSE-MIT) |
| memchr | 2.8.3 | Unlicense OR MIT | [COPYING](legal/rust/memchr-2.8.3/COPYING), [LICENSE-MIT](legal/rust/memchr-2.8.3/LICENSE-MIT) |
| memoffset | 0.9.1 | MIT | [LICENSE](legal/rust/memoffset-0.9.1/LICENSE) |
| mime | 0.3.17 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/mime-0.3.17/LICENSE-APACHE), [LICENSE-MIT](legal/rust/mime-0.3.17/LICENSE-MIT) |
| miniz_oxide | 0.8.9 | MIT OR Zlib OR Apache-2.0 | [LICENSE](legal/rust/miniz_oxide-0.8.9/LICENSE), [LICENSE-APACHE.md](legal/rust/miniz_oxide-0.8.9/LICENSE-APACHE.md), [LICENSE-MIT.md](legal/rust/miniz_oxide-0.8.9/LICENSE-MIT.md), [LICENSE-ZLIB.md](legal/rust/miniz_oxide-0.8.9/LICENSE-ZLIB.md) |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 | [LICENSE](legal/rust/miniz_oxide-0.9.1/LICENSE), [LICENSE-APACHE.md](legal/rust/miniz_oxide-0.9.1/LICENSE-APACHE.md), [LICENSE-MIT.md](legal/rust/miniz_oxide-0.9.1/LICENSE-MIT.md), [LICENSE-ZLIB.md](legal/rust/miniz_oxide-0.9.1/LICENSE-ZLIB.md) |
| mio | 1.2.4 | MIT | [LICENSE](legal/rust/mio-1.2.4/LICENSE) |
| muda | 0.19.3 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/muda-0.19.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/muda-0.19.3/LICENSE-MIT), [LICENSE.spdx](legal/rust/muda-0.19.3/LICENSE.spdx) |
| new_debug_unreachable | 1.0.6 | MIT | [LICENSE-MIT](legal/rust/new_debug_unreachable-1.0.6/LICENSE-MIT) |
| nix | 0.31.3 | MIT | [LICENSE](legal/rust/nix-0.31.3/LICENSE) |
| num-conv | 0.1.0 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/num-conv-0.1.0/LICENSE-Apache), [LICENSE-MIT](legal/rust/num-conv-0.1.0/LICENSE-MIT) |
| num-traits | 0.2.19 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/num-traits-0.2.19/LICENSE-APACHE), [LICENSE-MIT](legal/rust/num-traits-0.2.19/LICENSE-MIT) |
| num_enum | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/num_enum-0.7.6/LICENSE-APACHE), [LICENSE-BSD](legal/rust/num_enum-0.7.6/LICENSE-BSD), [LICENSE-MIT](legal/rust/num_enum-0.7.6/LICENSE-MIT) |
| num_enum_derive | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/num_enum_derive-0.7.6/LICENSE-APACHE), [LICENSE-BSD](legal/rust/num_enum_derive-0.7.6/LICENSE-BSD), [LICENSE-MIT](legal/rust/num_enum_derive-0.7.6/LICENSE-MIT) |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/once_cell-1.21.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/once_cell-1.21.4/LICENSE-MIT) |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/opaque-debug-0.3.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/opaque-debug-0.3.1/LICENSE-MIT) |
| open | 5.4.4 | MIT | [LICENSE.md](legal/rust/open-5.4.4/LICENSE.md) |
| option-ext | 0.2.0 | MPL-2.0 | [LICENSE.txt](legal/rust/option-ext-0.2.0/LICENSE.txt) |
| ordered-stream | 0.2.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ordered-stream-0.2.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ordered-stream-0.2.0/LICENSE-MIT) |
| page_size | 0.6.0 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/page_size-0.6.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/page_size-0.6.0/LICENSE-MIT) |
| pango | 0.18.3 | MIT | [COPYRIGHT](legal/rust/pango-0.18.3/COPYRIGHT), [LICENSE](legal/rust/pango-0.18.3/LICENSE) |
| pango-sys | 0.18.0 | MIT | [LICENSE](legal/rust/pango-sys-0.18.0/LICENSE) |
| parking | 2.2.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/parking-2.2.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/parking-2.2.1/LICENSE-MIT), [LICENSE-THIRD-PARTY](legal/rust/parking-2.2.1/LICENSE-THIRD-PARTY) |
| parking_lot | 0.12.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/parking_lot-0.12.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/parking_lot-0.12.5/LICENSE-MIT) |
| parking_lot_core | 0.9.12 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/parking_lot_core-0.9.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/parking_lot_core-0.9.12/LICENSE-MIT) |
| password-hash | 0.5.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/password-hash-0.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/password-hash-0.5.0/LICENSE-MIT) |
| pbkdf2 | 0.12.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/pbkdf2-0.12.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/pbkdf2-0.12.2/LICENSE-MIT) |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/percent-encoding-2.3.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/percent-encoding-2.3.2/LICENSE-MIT) |
| phf | 0.13.1 | MIT | [LICENSE](legal/rust/phf-0.13.1/LICENSE) |
| phf_codegen | 0.13.1 | MIT | [LICENSE](legal/rust/phf_codegen-0.13.1/LICENSE) |
| phf_generator | 0.13.1 | MIT | [LICENSE](legal/rust/phf_generator-0.13.1/LICENSE) |
| phf_macros | 0.13.1 | MIT | [LICENSE](legal/rust/phf_macros-0.13.1/LICENSE) |
| phf_shared | 0.13.1 | MIT | [LICENSE](legal/rust/phf_shared-0.13.1/LICENSE) |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/pin-project-lite-0.2.17/LICENSE-APACHE), [LICENSE-MIT](legal/rust/pin-project-lite-0.2.17/LICENSE-MIT) |
| piper | 0.2.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/piper-0.2.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/piper-0.2.5/LICENSE-MIT) |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/pkg-config-0.3.34/LICENSE-APACHE), [LICENSE-MIT](legal/rust/pkg-config-0.3.34/LICENSE-MIT) |
| plist | 1.8.0 | MIT | [LICENCE](legal/rust/plist-1.8.0/LICENCE) |
| png | 0.17.16 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/png-0.17.16/LICENSE-APACHE), [LICENSE-MIT](legal/rust/png-0.17.16/LICENSE-MIT) |
| png | 0.18.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/png-0.18.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/png-0.18.1/LICENSE-MIT) |
| polling | 3.11.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/polling-3.11.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/polling-3.11.0/LICENSE-MIT) |
| pollster | 0.4.0 | Apache-2.0/MIT | [LICENSE-APACHE](legal/rust/pollster-0.4.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/pollster-0.4.0/LICENSE-MIT) |
| poly1305 | 0.8.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/poly1305-0.8.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/poly1305-0.8.0/LICENSE-MIT) |
| potential_utf | 0.1.6 | Unicode-3.0 | [LICENSE](legal/rust/potential_utf-0.1.6/LICENSE) |
| powerfmt | 0.2.1 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/powerfmt-0.2.1/LICENSE-Apache), [LICENSE-MIT](legal/rust/powerfmt-0.2.1/LICENSE-MIT) |
| ppv-lite86 | 0.2.21 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ppv-lite86-0.2.21/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ppv-lite86-0.2.21/LICENSE-MIT) |
| precomputed-hash | 0.1.1 | MIT | [LICENSE](legal/rust/precomputed-hash-0.1.1/LICENSE) |
| proc-macro-crate | 1.3.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro-crate-1.3.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro-crate-1.3.1/LICENSE-MIT) |
| proc-macro-crate | 2.0.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro-crate-2.0.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro-crate-2.0.2/LICENSE-MIT) |
| proc-macro-crate | 3.5.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro-crate-3.5.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro-crate-3.5.0/LICENSE-MIT) |
| proc-macro-error | 1.0.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro-error-1.0.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro-error-1.0.4/LICENSE-MIT) |
| proc-macro-error-attr | 1.0.4 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro-error-attr-1.0.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro-error-attr-1.0.4/LICENSE-MIT) |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/proc-macro2-1.0.107/LICENSE-APACHE), [LICENSE-MIT](legal/rust/proc-macro2-1.0.107/LICENSE-MIT) |
| quick-xml | 0.38.4 | MIT | [LICENSE-MIT.md](legal/rust/quick-xml-0.38.4/LICENSE-MIT.md) |
| quick-xml | 0.41.0 | MIT | [LICENSE-MIT.md](legal/rust/quick-xml-0.41.0/LICENSE-MIT.md) |
| quinn | 0.11.12 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/quinn-0.11.12/LICENSE-APACHE), [LICENSE-MIT](legal/rust/quinn-0.11.12/LICENSE-MIT) |
| quinn-proto | 0.11.19 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/quinn-proto-0.11.19/LICENSE-APACHE), [LICENSE-MIT](legal/rust/quinn-proto-0.11.19/LICENSE-MIT) |
| quinn-udp | 0.5.16 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/quinn-udp-0.5.16/LICENSE-APACHE), [LICENSE-MIT](legal/rust/quinn-udp-0.5.16/LICENSE-MIT) |
| quote | 1.0.47 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/quote-1.0.47/LICENSE-APACHE), [LICENSE-MIT](legal/rust/quote-1.0.47/LICENSE-MIT) |
| rand | 0.10.3 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand-0.10.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand-0.10.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand-0.10.3/LICENSE-MIT) |
| rand | 0.9.5 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand-0.9.5/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand-0.9.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand-0.9.5/LICENSE-MIT) |
| rand_chacha | 0.9.0 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand_chacha-0.9.0/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand_chacha-0.9.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand_chacha-0.9.0/LICENSE-MIT) |
| rand_core | 0.10.1 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand_core-0.10.1/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand_core-0.10.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand_core-0.10.1/LICENSE-MIT) |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand_core-0.6.4/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand_core-0.6.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand_core-0.6.4/LICENSE-MIT) |
| rand_core | 0.9.5 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand_core-0.9.5/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand_core-0.9.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand_core-0.9.5/LICENSE-MIT) |
| rand_pcg | 0.10.2 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/rand_pcg-0.10.2/COPYRIGHT), [LICENSE-APACHE](legal/rust/rand_pcg-0.10.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rand_pcg-0.10.2/LICENSE-MIT) |
| raw-window-handle | 0.6.2 | MIT OR Apache-2.0 OR Zlib | [LICENSE-APACHE.md](legal/rust/raw-window-handle-0.6.2/LICENSE-APACHE.md), [LICENSE-MIT.md](legal/rust/raw-window-handle-0.6.2/LICENSE-MIT.md), [LICENSE-ZLIB.md](legal/rust/raw-window-handle-0.6.2/LICENSE-ZLIB.md) |
| ref-cast | 1.0.27 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ref-cast-1.0.27/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ref-cast-1.0.27/LICENSE-MIT) |
| ref-cast-impl | 1.0.27 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/ref-cast-impl-1.0.27/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ref-cast-impl-1.0.27/LICENSE-MIT) |
| regex | 1.13.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/regex-1.13.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/regex-1.13.1/LICENSE-MIT) |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/regex-automata-0.4.18/LICENSE-APACHE), [LICENSE-MIT](legal/rust/regex-automata-0.4.18/LICENSE-MIT) |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/regex-syntax-0.8.11/LICENSE-APACHE), [LICENSE-MIT](legal/rust/regex-syntax-0.8.11/LICENSE-MIT), [LICENSE-UNICODE](legal/rust/regex-syntax-0.8.11/src/unicode_tables/LICENSE-UNICODE) |
| reqwest | 0.12.28 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/reqwest-0.12.28/LICENSE-APACHE), [LICENSE-MIT](legal/rust/reqwest-0.12.28/LICENSE-MIT) |
| rfd | 0.16.0 | MIT | [LICENSE](legal/rust/rfd-0.16.0/LICENSE) |
| ring | 0.17.14 | Apache-2.0 AND ISC | [LICENSE](legal/rust/ring-0.17.14/LICENSE), [LICENSE-BoringSSL](legal/rust/ring-0.17.14/LICENSE-BoringSSL), [LICENSE-other-bits](legal/rust/ring-0.17.14/LICENSE-other-bits), [LICENSE-APACHE](legal/rust/ring-0.17.14/src/polyfill/once_cell/LICENSE-APACHE), [LICENSE-MIT](legal/rust/ring-0.17.14/src/polyfill/once_cell/LICENSE-MIT), [LICENSE](legal/rust/ring-0.17.14/third_party/fiat/LICENSE) |
| rusqlite | 0.32.1 | MIT | [LICENSE](legal/rust/rusqlite-0.32.1/LICENSE) |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/rustc-hash-2.1.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rustc-hash-2.1.3/LICENSE-MIT) |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/rustc_version-0.4.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rustc_version-0.4.1/LICENSE-MIT) |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/rustix-1.1.5/COPYRIGHT), [LICENSE-APACHE](legal/rust/rustix-1.1.5/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/rustix-1.1.5/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/rustix-1.1.5/LICENSE-MIT) |
| rustix-linux-procfs | 0.1.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/rustix-linux-procfs-0.1.1/COPYRIGHT), [LICENSE-APACHE](legal/rust/rustix-linux-procfs-0.1.1/LICENSE-APACHE), [LICENSE-Apache-2.0_WITH_LLVM-exception](legal/rust/rustix-linux-procfs-0.1.1/LICENSE-Apache-2.0_WITH_LLVM-exception), [LICENSE-MIT](legal/rust/rustix-linux-procfs-0.1.1/LICENSE-MIT) |
| rustls | 0.23.45 | Apache-2.0 OR ISC OR MIT | [LICENSE-APACHE](legal/rust/rustls-0.23.45/LICENSE-APACHE), [LICENSE-ISC](legal/rust/rustls-0.23.45/LICENSE-ISC), [LICENSE-MIT](legal/rust/rustls-0.23.45/LICENSE-MIT) |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/rustls-pki-types-1.15.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rustls-pki-types-1.15.1/LICENSE-MIT) |
| rustls-webpki | 0.103.15 | ISC | [LICENSE](legal/rust/rustls-webpki-0.103.15/LICENSE) |
| rustversion | 1.0.23 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/rustversion-1.0.23/LICENSE-APACHE), [LICENSE-MIT](legal/rust/rustversion-1.0.23/LICENSE-MIT) |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 | [LICENSE-APACHE](legal/rust/ryu-1.0.23/LICENSE-APACHE), [LICENSE-BOOST](legal/rust/ryu-1.0.23/LICENSE-BOOST) |
| salsa20 | 0.10.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/salsa20-0.10.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/salsa20-0.10.2/LICENSE-MIT) |
| same-file | 1.0.6 | Unlicense/MIT | [COPYING](legal/rust/same-file-1.0.6/COPYING), [LICENSE-MIT](legal/rust/same-file-1.0.6/LICENSE-MIT) |
| schemars | 0.8.22 | MIT | [LICENSE](legal/rust/schemars-0.8.22/LICENSE) |
| schemars | 0.9.0 | MIT | [LICENSE](legal/rust/schemars-0.9.0/LICENSE) |
| schemars | 1.2.2 | MIT | [LICENSE](legal/rust/schemars-1.2.2/LICENSE) |
| schemars_derive | 0.8.22 | MIT | [LICENSE](legal/rust/schemars_derive-0.8.22/LICENSE) |
| scoped-tls | 1.0.1 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/scoped-tls-1.0.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/scoped-tls-1.0.1/LICENSE-MIT) |
| scopeguard | 1.2.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/scopeguard-1.2.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/scopeguard-1.2.0/LICENSE-MIT) |
| scrypt | 0.11.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/scrypt-0.11.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/scrypt-0.11.0/LICENSE-MIT) |
| selectors | 0.36.1 | MPL-2.0 | [MPL-2.0.txt](legal/upstream-retrieval/selectors-635e1a19d02960588a00e189bd4bd5bdb150ec3d/MPL-2.0.txt), [source-license-header.txt](legal/registry-provenance/selectors@0.36.1/source-license-header.txt) |
| semver | 1.0.28 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/semver-1.0.28/LICENSE-APACHE), [LICENSE-MIT](legal/rust/semver-1.0.28/LICENSE-MIT) |
| serde | 1.0.229 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde-1.0.229/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde-1.0.229/LICENSE-MIT) |
| serde-untagged | 0.1.9 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde-untagged-0.1.9/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde-untagged-0.1.9/LICENSE-MIT) |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_core-1.0.229/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_core-1.0.229/LICENSE-MIT) |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_derive-1.0.229/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_derive-1.0.229/LICENSE-MIT) |
| serde_derive_internals | 0.29.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_derive_internals-0.29.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_derive_internals-0.29.1/LICENSE-MIT) |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_json-1.0.151/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_json-1.0.151/LICENSE-MIT) |
| serde_repr | 0.1.21 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_repr-0.1.21/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_repr-0.1.21/LICENSE-MIT) |
| serde_spanned | 0.6.9 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_spanned-0.6.9/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_spanned-0.6.9/LICENSE-MIT) |
| serde_spanned | 1.1.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_spanned-1.1.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_spanned-1.1.2/LICENSE-MIT) |
| serde_urlencoded | 0.7.1 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_urlencoded-0.7.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_urlencoded-0.7.1/LICENSE-MIT) |
| serde_with | 3.17.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_with-3.17.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_with-3.17.0/LICENSE-MIT) |
| serde_with_macros | 3.17.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serde_with_macros-3.17.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serde_with_macros-3.17.0/LICENSE-MIT) |
| serialize-to-javascript | 0.1.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serialize-to-javascript-0.1.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serialize-to-javascript-0.1.2/LICENSE-MIT) |
| serialize-to-javascript-impl | 0.1.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/serialize-to-javascript-impl-0.1.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/serialize-to-javascript-impl-0.1.2/LICENSE-MIT) |
| servo_arc | 0.4.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/servo_arc-0.4.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/servo_arc-0.4.3/LICENSE-MIT) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/sha2-0.10.9/LICENSE-APACHE), [LICENSE-MIT](legal/rust/sha2-0.10.9/LICENSE-MIT) |
| shlex | 2.0.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/shlex-2.0.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/shlex-2.0.1/LICENSE-MIT) |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/signal-hook-registry-1.4.8/LICENSE-APACHE), [LICENSE-MIT](legal/rust/signal-hook-registry-1.4.8/LICENSE-MIT) |
| simd-adler32 | 0.3.10 | MIT | [LICENSE.md](legal/rust/simd-adler32-0.3.10/LICENSE.md) |
| siphasher | 1.0.4 | MIT OR Apache-2.0 | [COPYING](legal/rust/siphasher-1.0.4/COPYING), [LICENSE-APACHE](legal/rust/siphasher-1.0.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/siphasher-1.0.4/LICENSE-MIT) |
| slab | 0.4.12 | MIT | [LICENSE](legal/rust/slab-0.4.12/LICENSE) |
| smallvec | 1.16.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/smallvec-1.16.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/smallvec-1.16.2/LICENSE-MIT) |
| socket2 | 0.6.5 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/socket2-0.6.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/socket2-0.6.5/LICENSE-MIT) |
| soup3 | 0.5.0 | MIT | [LICENSE](legal/rust/soup3-0.5.0/LICENSE) |
| soup3-sys | 0.5.0 | MIT | [LICENSE](legal/rust/soup3-sys-0.5.0/LICENSE) |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/stable_deref_trait-1.2.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/stable_deref_trait-1.2.1/LICENSE-MIT) |
| string_cache | 0.9.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/string_cache-0.9.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/string_cache-0.9.0/LICENSE-MIT) |
| string_cache_codegen | 0.6.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/string_cache_codegen-0.6.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/string_cache_codegen-0.6.1/LICENSE-MIT) |
| strsim | 0.11.1 | MIT | [LICENSE](legal/rust/strsim-0.11.1/LICENSE) |
| subtle | 2.6.1 | BSD-3-Clause | [LICENSE](legal/rust/subtle-2.6.1/LICENSE) |
| syn | 1.0.109 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/syn-1.0.109/LICENSE-APACHE), [LICENSE-MIT](legal/rust/syn-1.0.109/LICENSE-MIT) |
| syn | 2.0.119 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/syn-2.0.119/LICENSE-APACHE), [LICENSE-MIT](legal/rust/syn-2.0.119/LICENSE-MIT) |
| syn | 3.0.6 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/syn-3.0.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/syn-3.0.6/LICENSE-MIT) |
| sync_wrapper | 1.0.2 | Apache-2.0 | [LICENSE](legal/rust/sync_wrapper-1.0.2/LICENSE) |
| synstructure | 0.14.0 | MIT | [LICENSE](legal/rust/synstructure-0.14.0/LICENSE) |
| system-deps | 6.2.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/system-deps-6.2.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/system-deps-6.2.2/LICENSE-MIT) |
| tao | 0.35.3 | Apache-2.0 | [LICENSE](legal/rust/tao-0.35.3/LICENSE), [LICENSE.spdx](legal/rust/tao-0.35.3/LICENSE.spdx) |
| target-lexicon | 0.12.16 | Apache-2.0 WITH LLVM-exception | [LICENSE](legal/rust/target-lexicon-0.12.16/LICENSE) |
| tauri | 2.11.6 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-2.11.6/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-2.11.6/LICENSE_MIT) |
| tauri-build | 2.6.3 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-build-2.6.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-build-2.6.3/LICENSE_MIT) |
| tauri-codegen | 2.6.3 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-codegen-2.6.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-codegen-2.6.3/LICENSE_MIT) |
| tauri-macros | 2.6.3 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-macros-2.6.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-macros-2.6.3/LICENSE_MIT) |
| tauri-plugin | 2.6.3 | Apache-2.0 OR MIT | [LICENSE_MIT](legal/upstream-retrieval/tauriplugin-6f6ab1207bb3923c2721fbc67d2fdb1c8deb0c7a/LICENSE_MIT), [LICENSE_APACHE-2.0](legal/upstream-retrieval/tauriplugin-6f6ab1207bb3923c2721fbc67d2fdb1c8deb0c7a/LICENSE_APACHE-2.0) |
| tauri-plugin-dialog | 2.7.3 | Apache-2.0 OR MIT | [LICENSE.spdx](legal/rust/tauri-plugin-dialog-2.7.3/LICENSE.spdx), [LICENSE_APACHE-2.0](legal/rust/tauri-plugin-dialog-2.7.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-plugin-dialog-2.7.3/LICENSE_MIT) |
| tauri-plugin-fs | 2.5.2 | Apache-2.0 OR MIT | [LICENSE.spdx](legal/rust/tauri-plugin-fs-2.5.2/LICENSE.spdx), [LICENSE_APACHE-2.0](legal/rust/tauri-plugin-fs-2.5.2/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-plugin-fs-2.5.2/LICENSE_MIT) |
| tauri-plugin-opener | 2.5.5 | Apache-2.0 OR MIT | [LICENSE.spdx](legal/rust/tauri-plugin-opener-2.5.5/LICENSE.spdx), [LICENSE_APACHE-2.0](legal/rust/tauri-plugin-opener-2.5.5/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-plugin-opener-2.5.5/LICENSE_MIT) |
| tauri-plugin-single-instance | 2.4.5 | Apache-2.0 OR MIT | [LICENSE.spdx](legal/rust/tauri-plugin-single-instance-2.4.5/LICENSE.spdx), [LICENSE_APACHE-2.0](legal/rust/tauri-plugin-single-instance-2.4.5/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-plugin-single-instance-2.4.5/LICENSE_MIT) |
| tauri-runtime | 2.11.3 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-runtime-2.11.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-runtime-2.11.3/LICENSE_MIT) |
| tauri-runtime-wry | 2.11.4 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-runtime-wry-2.11.4/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-runtime-wry-2.11.4/LICENSE_MIT) |
| tauri-utils | 2.9.3 | Apache-2.0 OR MIT | [LICENSE_APACHE-2.0](legal/rust/tauri-utils-2.9.3/LICENSE_APACHE-2.0), [LICENSE_MIT](legal/rust/tauri-utils-2.9.3/LICENSE_MIT) |
| tauri-winres | 0.3.6 | MIT | [LICENSE](legal/rust/tauri-winres-0.3.6/LICENSE) |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/tempfile-3.27.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/tempfile-3.27.0/LICENSE-MIT) |
| tendril | 0.5.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/tendril-0.5.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/tendril-0.5.1/LICENSE-MIT) |
| thiserror | 1.0.69 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/thiserror-1.0.69/LICENSE-APACHE), [LICENSE-MIT](legal/rust/thiserror-1.0.69/LICENSE-MIT) |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/thiserror-2.0.21/LICENSE-APACHE), [LICENSE-MIT](legal/rust/thiserror-2.0.21/LICENSE-MIT) |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/thiserror-impl-1.0.69/LICENSE-APACHE), [LICENSE-MIT](legal/rust/thiserror-impl-1.0.69/LICENSE-MIT) |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/thiserror-impl-2.0.21/LICENSE-APACHE), [LICENSE-MIT](legal/rust/thiserror-impl-2.0.21/LICENSE-MIT) |
| time | 0.3.45 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/time-0.3.45/LICENSE-Apache), [LICENSE-MIT](legal/rust/time-0.3.45/LICENSE-MIT) |
| time-core | 0.1.7 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/time-core-0.1.7/LICENSE-Apache), [LICENSE-MIT](legal/rust/time-core-0.1.7/LICENSE-MIT) |
| time-macros | 0.2.25 | MIT OR Apache-2.0 | [LICENSE-Apache](legal/rust/time-macros-0.2.25/LICENSE-Apache), [LICENSE-MIT](legal/rust/time-macros-0.2.25/LICENSE-MIT) |
| tinystr | 0.8.4 | Unicode-3.0 | [LICENSE](legal/rust/tinystr-0.8.4/LICENSE) |
| tinyvec | 1.13.3 | Zlib OR Apache-2.0 OR MIT | [LICENSE-APACHE.md](legal/rust/tinyvec-1.13.3/LICENSE-APACHE.md), [LICENSE-MIT.md](legal/rust/tinyvec-1.13.3/LICENSE-MIT.md), [LICENSE-ZLIB.md](legal/rust/tinyvec-1.13.3/LICENSE-ZLIB.md) |
| tokio | 1.53.2 | MIT | [LICENSE](legal/rust/tokio-1.53.2/LICENSE) |
| tokio-rustls | 0.26.6 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/tokio-rustls-0.26.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/tokio-rustls-0.26.6/LICENSE-MIT) |
| tokio-util | 0.7.20 | MIT | [LICENSE](legal/rust/tokio-util-0.7.20/LICENSE) |
| toml | 0.8.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml-0.8.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml-0.8.2/LICENSE-MIT) |
| toml | 0.9.12+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml-0.9.12+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml-0.9.12+spec-1.1.0/LICENSE-MIT) |
| toml | 1.1.7+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml-1.1.7+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml-1.1.7+spec-1.1.0/LICENSE-MIT) |
| toml_datetime | 0.6.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_datetime-0.6.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_datetime-0.6.3/LICENSE-MIT) |
| toml_datetime | 0.7.5+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_datetime-0.7.5+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_datetime-0.7.5+spec-1.1.0/LICENSE-MIT) |
| toml_datetime | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_datetime-1.1.2+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_datetime-1.1.2+spec-1.1.0/LICENSE-MIT) |
| toml_edit | 0.19.15 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_edit-0.19.15/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_edit-0.19.15/LICENSE-MIT) |
| toml_edit | 0.20.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_edit-0.20.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_edit-0.20.2/LICENSE-MIT) |
| toml_edit | 0.25.16+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_edit-0.25.16+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_edit-0.25.16+spec-1.1.0/LICENSE-MIT) |
| toml_parser | 1.1.4+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_parser-1.1.4+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_parser-1.1.4+spec-1.1.0/LICENSE-MIT) |
| toml_writer | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/toml_writer-1.1.3+spec-1.1.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/toml_writer-1.1.3+spec-1.1.0/LICENSE-MIT) |
| tower | 0.5.3 | MIT | [LICENSE](legal/rust/tower-0.5.3/LICENSE) |
| tower-http | 0.6.11 | MIT | [LICENSE](legal/rust/tower-http-0.6.11/LICENSE) |
| tower-layer | 0.3.3 | MIT | [LICENSE](legal/rust/tower-layer-0.3.3/LICENSE) |
| tower-service | 0.3.3 | MIT | [LICENSE](legal/rust/tower-service-0.3.3/LICENSE) |
| tracing | 0.1.44 | MIT | [LICENSE](legal/rust/tracing-0.1.44/LICENSE) |
| tracing-attributes | 0.1.31 | MIT | [LICENSE](legal/rust/tracing-attributes-0.1.31/LICENSE) |
| tracing-core | 0.1.36 | MIT | [LICENSE](legal/rust/tracing-core-0.1.36/LICENSE), [LICENSE](legal/rust/tracing-core-0.1.36/src/spin/LICENSE) |
| tray-icon | 0.24.2 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/tray-icon-0.24.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/tray-icon-0.24.2/LICENSE-MIT), [LICENSE.spdx](legal/rust/tray-icon-0.24.2/LICENSE.spdx) |
| try-lock | 0.2.5 | MIT | [LICENSE](legal/rust/try-lock-0.2.5/LICENSE) |
| typeid | 1.0.3 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/typeid-1.0.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/typeid-1.0.3/LICENSE-MIT) |
| typenum | 1.20.1 | MIT OR Apache-2.0 | [LICENSE](legal/rust/typenum-1.20.1/LICENSE), [LICENSE-APACHE](legal/rust/typenum-1.20.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/typenum-1.20.1/LICENSE-MIT) |
| unic-char-property | 0.9.0 | MIT/Apache-2.0 | [LICENSE-MIT](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-APACHE), [COPYRIGHT.md](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/COPYRIGHT.md), [AUTHORS](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/AUTHORS) |
| unic-char-range | 0.9.0 | MIT/Apache-2.0 | [LICENSE-MIT](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-APACHE), [COPYRIGHT.md](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/COPYRIGHT.md), [AUTHORS](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/AUTHORS) |
| unic-common | 0.9.0 | MIT/Apache-2.0 | [LICENSE-MIT](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-APACHE), [COPYRIGHT.md](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/COPYRIGHT.md), [AUTHORS](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/AUTHORS) |
| unic-ucd-ident | 0.9.0 | MIT/Apache-2.0 | [LICENSE-MIT](legal/upstream-retrieval/unicident-8a6ce83063d90b91ae2ce59eddb803edd393fca9/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/unicident-8a6ce83063d90b91ae2ce59eddb803edd393fca9/LICENSE-APACHE), [COPYRIGHT.md](legal/upstream-retrieval/unicident-8a6ce83063d90b91ae2ce59eddb803edd393fca9/COPYRIGHT.md), [AUTHORS](legal/upstream-retrieval/unicident-8a6ce83063d90b91ae2ce59eddb803edd393fca9/AUTHORS) |
| unic-ucd-version | 0.9.0 | MIT/Apache-2.0 | [LICENSE-MIT](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-MIT), [LICENSE-APACHE](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/LICENSE-APACHE), [COPYRIGHT.md](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/COPYRIGHT.md), [AUTHORS](legal/upstream-retrieval/unic-5878605364af97a3358368a6eaef02104af2e016/AUTHORS) |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | [LICENSE-APACHE](legal/rust/unicode-ident-1.0.26/LICENSE-APACHE), [LICENSE-MIT](legal/rust/unicode-ident-1.0.26/LICENSE-MIT), [LICENSE-UNICODE](legal/rust/unicode-ident-1.0.26/LICENSE-UNICODE) |
| unicode-normalization | 0.1.24 | MIT/Apache-2.0 | [COPYRIGHT](legal/rust/unicode-normalization-0.1.24/COPYRIGHT), [LICENSE-APACHE](legal/rust/unicode-normalization-0.1.24/LICENSE-APACHE), [LICENSE-MIT](legal/rust/unicode-normalization-0.1.24/LICENSE-MIT) |
| unicode-segmentation | 1.13.3 | MIT OR Apache-2.0 | [COPYRIGHT](legal/rust/unicode-segmentation-1.13.3/COPYRIGHT), [LICENSE-APACHE](legal/rust/unicode-segmentation-1.13.3/LICENSE-APACHE), [LICENSE-MIT](legal/rust/unicode-segmentation-1.13.3/LICENSE-MIT) |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/universal-hash-0.5.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/universal-hash-0.5.1/LICENSE-MIT) |
| untrusted | 0.9.0 | ISC | [LICENSE.txt](legal/rust/untrusted-0.9.0/LICENSE.txt) |
| url | 2.5.8 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/url-2.5.8/LICENSE-APACHE), [LICENSE-MIT](legal/rust/url-2.5.8/LICENSE-MIT) |
| urlencoding | 2.1.3 | MIT | [LICENSE](legal/rust/urlencoding-2.1.3/LICENSE) |
| urlpattern | 0.3.0 | MIT | [LICENSE](legal/rust/urlpattern-0.3.0/LICENSE) |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT | [COPYRIGHT](legal/rust/utf8_iter-1.0.4/COPYRIGHT), [LICENSE-APACHE](legal/rust/utf8_iter-1.0.4/LICENSE-APACHE), [LICENSE-MIT](legal/rust/utf8_iter-1.0.4/LICENSE-MIT) |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/utf8parse-0.2.2/LICENSE-APACHE), [LICENSE-MIT](legal/rust/utf8parse-0.2.2/LICENSE-MIT) |
| uuid | 1.26.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/uuid-1.26.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/uuid-1.26.1/LICENSE-MIT) |
| uuid | 1.27.0 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/uuid-1.27.0/LICENSE-APACHE), [LICENSE-MIT](legal/rust/uuid-1.27.0/LICENSE-MIT) |
| vcpkg | 0.2.15 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/vcpkg-0.2.15/LICENSE-APACHE), [LICENSE-MIT](legal/rust/vcpkg-0.2.15/LICENSE-MIT) |
| version-compare | 0.2.1 | MIT | [LICENSE](legal/rust/version-compare-0.2.1/LICENSE) |
| version_check | 0.9.5 | MIT/Apache-2.0 | [LICENSE-APACHE](legal/rust/version_check-0.9.5/LICENSE-APACHE), [LICENSE-MIT](legal/rust/version_check-0.9.5/LICENSE-MIT) |
| walkdir | 2.5.0 | Unlicense/MIT | [COPYING](legal/rust/walkdir-2.5.0/COPYING), [LICENSE-MIT](legal/rust/walkdir-2.5.0/LICENSE-MIT) |
| want | 0.3.2 | MIT | [LICENSE](legal/rust/want-0.3.2/LICENSE) |
| wayland-backend | 0.3.17 | MIT | [LICENSE.txt](legal/rust/wayland-backend-0.3.17/LICENSE.txt) |
| wayland-client | 0.31.15 | MIT | [LICENSE.txt](legal/rust/wayland-client-0.31.15/LICENSE.txt) |
| wayland-protocols | 0.32.12 | MIT | [LICENSE.txt](legal/rust/wayland-protocols-0.32.12/LICENSE.txt), [COPYING](legal/rust/wayland-protocols-0.32.12/protocols/COPYING) |
| wayland-scanner | 0.31.11 | MIT | [LICENSE.txt](legal/rust/wayland-scanner-0.31.11/LICENSE.txt) |
| wayland-sys | 0.31.11 | MIT | [LICENSE.txt](legal/rust/wayland-sys-0.31.11/LICENSE.txt) |
| web_atoms | 0.2.6 | MIT OR Apache-2.0 | [LICENSE-APACHE](legal/rust/web_atoms-0.2.6/LICENSE-APACHE), [LICENSE-MIT](legal/rust/web_atoms-0.2.6/LICENSE-MIT) |
| webkit2gtk | 2.0.2 | MIT | [LICENSE](legal/rust/webkit2gtk-2.0.2/LICENSE) |
| webkit2gtk-sys | 2.0.2 | MIT | [LICENSE](legal/rust/webkit2gtk-sys-2.0.2/LICENSE) |
| webpki-roots | 1.0.9 | CDLA-Permissive-2.0 | [LICENSE](legal/rust/webpki-roots-1.0.9/LICENSE) |
| winnow | 0.5.40 | MIT | [LICENSE-MIT](legal/rust/winnow-0.5.40/LICENSE-MIT) |
| winnow | 0.7.15 | MIT | [LICENSE-MIT](legal/rust/winnow-0.7.15/LICENSE-MIT) |
| winnow | 1.0.4 | MIT | [LICENSE-MIT](legal/rust/winnow-1.0.4/LICENSE-MIT) |
| writeable | 0.6.4 | Unicode-3.0 | [LICENSE](legal/rust/writeable-0.6.4/LICENSE) |
| wry | 0.55.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/wry-0.55.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/wry-0.55.1/LICENSE-MIT), [LICENSE.spdx](legal/rust/wry-0.55.1/LICENSE.spdx) |
| x11 | 2.21.0 | MIT | [LICENSE-MIT](legal/rust/x11-2.21.0/LICENSE-MIT) |
| x11-dl | 2.21.0 | MIT | [LICENSE-MIT](legal/rust/x11-dl-2.21.0/LICENSE-MIT) |
| yoke | 0.8.3 | Unicode-3.0 | [LICENSE](legal/rust/yoke-0.8.3/LICENSE) |
| yoke-derive | 0.8.4 | Unicode-3.0 | [LICENSE](legal/rust/yoke-derive-0.8.4/LICENSE) |
| zbus | 5.13.2 | MIT | [LICENSE](legal/rust/zbus-5.13.2/LICENSE) |
| zbus_macros | 5.13.2 | MIT | [LICENSE](legal/rust/zbus_macros-5.13.2/LICENSE) |
| zbus_names | 4.3.1 | MIT | [LICENSE](legal/rust/zbus_names-4.3.1/LICENSE) |
| zerocopy | 0.8.61 | BSD-2-Clause OR Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/zerocopy-0.8.61/LICENSE-APACHE), [LICENSE-BSD](legal/rust/zerocopy-0.8.61/LICENSE-BSD), [LICENSE-MIT](legal/rust/zerocopy-0.8.61/LICENSE-MIT) |
| zerocopy-derive | 0.8.61 | BSD-2-Clause OR Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/zerocopy-derive-0.8.61/LICENSE-APACHE), [LICENSE-BSD](legal/rust/zerocopy-derive-0.8.61/LICENSE-BSD), [LICENSE-MIT](legal/rust/zerocopy-derive-0.8.61/LICENSE-MIT) |
| zerofrom | 0.1.8 | Unicode-3.0 | [LICENSE](legal/rust/zerofrom-0.1.8/LICENSE) |
| zerofrom-derive | 0.1.8 | Unicode-3.0 | [LICENSE](legal/rust/zerofrom-derive-0.1.8/LICENSE) |
| zeroize | 1.9.1 | Apache-2.0 OR MIT | [LICENSE-APACHE](legal/rust/zeroize-1.9.1/LICENSE-APACHE), [LICENSE-MIT](legal/rust/zeroize-1.9.1/LICENSE-MIT) |
| zerotrie | 0.2.5 | Unicode-3.0 | [LICENSE](legal/rust/zerotrie-0.2.5/LICENSE) |
| zerovec | 0.11.8 | Unicode-3.0 | [LICENSE](legal/rust/zerovec-0.11.8/LICENSE) |
| zerovec-derive | 0.11.6 | Unicode-3.0 | [LICENSE](legal/rust/zerovec-derive-0.11.6/LICENSE) |
| zlib-rs | 0.6.8 | Zlib | [LICENSE](legal/rust/zlib-rs-0.6.8/LICENSE) |
| zmij | 1.0.23 | MIT | [LICENSE-MIT](legal/rust/zmij-1.0.23/LICENSE-MIT) |
| zvariant | 5.9.2 | MIT | [LICENSE](legal/rust/zvariant-5.9.2/LICENSE) |
| zvariant_derive | 5.9.2 | MIT | [LICENSE](legal/rust/zvariant_derive-5.9.2/LICENSE) |
| zvariant_utils | 3.3.0 | MIT | [LICENSE](legal/rust/zvariant_utils-3.3.0/LICENSE) |

## Reproduce offline

From `apps/desktop`, run `python3 scripts/collect-runtime-notices.py --node-modules /path/to/existing/desktop-shell/node_modules`. It uses `cargo metadata --offline --locked`, does not build or install packages, verifies cached production npm versions against both lockfiles, and writes only `legal/`. Use an existing local cache matching the release locks; a cache miss must be resolved deliberately rather than silently changing locks.
