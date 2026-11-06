# Vault crypto component notices

These license texts are packaged as Android library assets and merged into the
application APK. Versions refer to the binaries used by `core:crypto`.

| Component | Version | License | License file | Upstream source |
| --- | --- | --- | --- | --- |
| Bouncy Castle `bcprov-jdk18on` | 1.85.2 | MIT X Consortium-style | `BOUNCY-CASTLE-LICENSE.html` | https://github.com/bcgit/bc-java/tree/r1rv85v2 |
| Lazysodium Android | 5.2.0 | MPL-2.0 | `LAZYSODIUM-MPL-2.0-LICENSE` | https://github.com/terl/lazysodium-android/tree/v5.2.0 |
| libsodium native security backport | 1.0.20 + ad3004e | ISC | `LIBSODIUM-ISC-LICENSE` | https://github.com/jedisct1/libsodium/commit/ad3004ec8731730e93fcfbbc824e67eadc1c1bae |
| JNA Android AAR | 5.17.0 | Apache-2.0 option | `JNA-APACHE-2.0-LICENSE` | https://github.com/java-native-access/jna/tree/5.17.0 |
| EME transform adapted from `rfjakob/eme` | v1.2.0 | MIT | `EME-MIT-LICENSE` | https://github.com/rfjakob/eme/tree/v1.2.0 |

The Kotlin EME transform adapts the upstream Go `eme.go` algorithm to Bouncy
Castle AES, retaining copyright (c) 2015 Jakob Unterwurzacher and the MIT
license. The upstream source is pinned through rclone's `go.mod` to v1.2.0.

Lazysodium includes native libsodium for arm64-v8a and x86_64. The explicit JNA
AAR dependency supplies Android's native `libjnidispatch` and excludes the JAR
transitive dependency that would duplicate Java classes.

Raiun's distinct local native-backport artifact retains Lazysodium Android 5.2.0
Java payloads and license attribution. Its native libraries use the official
signature-verified libsodium 1.0.20 source plus the exact upstream point-validation
security fix above. Unused 32-bit native libraries are omitted. Source hashes,
patches and build provenance are recorded in `third_party/native-security-fixes/`.
