# Local native security backport bundles

These are local, checksum-pinned Maven AARs for the Raiun Android candidate. They are not publisher releases. The Maven repository is under `maven/`. Each coordinate has a matching POM and AAR only; no Gradle module metadata or generated Maven sidecar checksums are supplied. The unchanged dependency declarations remain in the original POM-derived files.

## Coordinates

- `app.raiun.vendor:lazysodium-android:5.2.0-raiun-native.1`
- `app.raiun.vendor:scanner-processing-opencv:0.8.0-beta.1-raiun-native.1`

The original public origins are Lazysodium Android tag [`d8b1885cff127a47b5a3bd9bcf0a53d36c372855`](https://github.com/terl/lazysodium-android/tree/d8b1885cff127a47b5a3bd9bcf0a53d36c372855), original AAR SHA-256 `b5378c1d9db2573d61b304e89cf83db187a05c3e4ff081d9b2ef3d0bb00ca314`, and scanner source commit [`8d9a451c27ed87d20110d25dcedb81001e0f521f`](https://github.com/phillip9933/open-android-doc-scanner/tree/8d9a451c27ed87d20110d25dcedb81001e0f521f), original AAR SHA-256 `6de7e504bda98f1f4a8d9c2451196061e0662ee1848f3278ab14c03cc3539375`.

The Sodium native source is official libsodium `1.0.20-RELEASE`, [source archive](https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz), SHA-256 `ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19`, with the upstream security backport [`ad3004ec8731730e93fcfbbc824e67eadc1c1bae`](https://github.com/jedisct1/libsodium/commit/ad3004ec8731730e93fcfbbc824e67eadc1c1bae). Its downloaded release source signature and trusted comment were verified before the recorded build.

The OpenCV native source is the public [`4.12.0` source archive](https://github.com/opencv/opencv/archive/refs/tags/4.12.0.zip), SHA-256 `fa3faf7581f1fa943c9e670cf57dd6ba1c5b4178f363a188a2c8bff1eb28b7e4`. The Raiun local source change is identified as `raiun-split-function-pointer-1`; it corrects function pointer signatures in `modules/core/src/split.dispatch.cpp`.

## Preserved payloads and attribution

For each AAR, only the native library members identified by its build provenance are replaced. The Sodium AAR omits its unsupported 32-bit `armeabi-v7a` and `x86` libraries to prevent an unpatched ABI from shipping. Scanner Java/classes, model/resources, embedded notices and license files, and original `libc++_shared.so` members retain their original payload bytes. POM license attribution and dependency declarations are preserved; only the local group, version, name, description, and scanner's published-with-Gradle-metadata marker are changed. The scanner marker is removed because this bundle intentionally has no `.module` file.

The Sodium wrapper keeps its original Mozilla Public License 2.0 attribution. Scanner/OpenCV attribution and all original scanner notice payloads remain unchanged inside its AAR, including Apache-2.0 project attribution and the OpenCV license/third-party notices. The upstream patch files are included under `sources/`; sanitized build records are under `provenance/`.

To rebuild libsodium, follow `provenance/libsodium-source-recipe.md`; its exact flags and per-ABI `configure` options are recorded in `provenance/libsodium-build.json`. That document is a recipe, not an executable build driver. The task-local fail-closed driver is outside this bundle at `outputs/android-native-findings-20261106/libsodium/build-native-backport.py`. No OpenCV source archive or build driver is vendored; its public URL, source and patch digests, NDK/API/compiler, modules, and output hashes are recorded in `provenance/opencv-build.json`.

`SHA256SUMS` covers every bundle file except itself. The listed Maven repository files are exactly the two AARs and their two POMs under `maven/`.
