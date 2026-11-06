# Android native dependency checks

The native checker verifies every packaged `.so` against checksum-pinned AAR
members and records source/build provenance separately from advisory coverage.
Raiun now uses two distinct, locally built native-only backport artifacts in
[the pinned bundle](../third_party/native-security-fixes/README.md). Their Java,
resources, models and `libc++_shared.so` payloads are unchanged; the reviewed
OpenCV and libsodium libraries carry the patches described below. They
are not upstream publisher releases; original public artifacts remain intact.

## Run locally

From `apps/android`, with Python 3.11+ and the standard library:

```sh
python3 scripts/test_check_native_dependencies.py
python3 scripts/check_native_dependencies.py \
  --inventory docs/release-audit/native/inventory.json \
  --pins gradle/runtime-artifact-pins.sha256 \
  --apk app/build/outputs/apk/release/app-release-unsigned.apk \
  --artifact-root "$HOME/.gradle/caches/modules-2/files-2.1" \
  --artifact-root .gradle/open-android-doc-scanner-0.8.0-beta.1/maven \
  --artifact-root third_party/native-security-fixes/maven \
  --scan --output build/native-review.json
```

Omit `--scan` for offline APK integrity only. Omit `--apk`/artifact roots to query
source advisories without claiming an APK build or byte check. The quality
workflow verifies the assembled release APK; the scheduled dependency workflow
queries source tags. The Maven checker also retains original upstream input
coordinates alongside the native forks, preserving advisory coverage for the
unchanged wrapper and scanner Java code.

Missing/unexpected libraries or ABIs, changed bytes, missing artifacts, changed
runtime pins and missing/changed source evidence fail as `unavailable` (exit 2).
ZIP decompression, size/count and malformed-data errors also fail explicitly.
Only a completed byte check produces `integrity.status=verified`. Debug-only
libraries are not silently allowlisted; use the release APK.

## Advisory results and reviewed resolutions

`--scan` queries the four explicit GIT repository/tag identities for OpenCV,
libsodium, JNA and ONNX Runtime using [OSV's documented form](https://google.github.io/osv.dev/post-v1-query/).
The base tags remain the query identities even for a locally patched build.
Timeouts, malformed responses and incomplete pagination remain unavailable.
An empty response is `no_matches_in_queried_sources`, never a claim that the
native code is free of vulnerabilities. Unsupported source mappings remain
explicit coverage gaps rather than guessed CPE/distro queries.

All raw advisory matches and independently known findings remain in the output.
The optional reviewed resolutions in [the inventory](release-audit/native/inventory.json)
add a resolved/unresolved summary. Each resolution must bind the exact current
component artifact set and hashes, plus hash-verified evidence files. Only
`fixed/source_patch_applied` and `not_affected/component_not_present` are allowed;
there is no blanket ignore rule or automatic unused-call suppression. A changed
artifact, missing proof or newly observed advisory requires renewed review.

Unresolved findings produce `attention_required` (exit 1 for `--scan`). Resolved
known findings produce `bounded_check_complete_with_coverage_gaps`; raw
`advisories.status` can still be `matches_found`. Integrity-only exit 0 is not
security clearance. Automation must inspect the separate statuses and review
summary. Neither a bounded source query nor these resolutions certify the whole
app or unknown/transitive native code.

## OpenCV and libsodium resolution — 6 November 2026

The [source/build and synthetic execution review](release-audit/native/security-backports.json)
binds the two patched AARs, source archives, patches and test evidence. The
complete inventory remains 20 libraries across arm64-v8a/x86_64 and seven AARs.

| Finding | Exact-candidate resolution |
| --- | --- |
| [OSV-2022-394](https://osv.dev/vulnerability/OSV-2022-394), incorrect function-pointer type in `cv::split` | **Fixed.** A local OpenCV 4.12.0 patch replaces incompatible dispatch casts with correctly typed wrappers and individually converts destination pointer values, avoiding a new `T**` aliasing problem. The original real core fails function-sanitized execution; the patched core passes 672 byte-exact checks over all eight depths, seven channel counts, contiguous/ROI matrices and both overloads. |
| [OSV-2023-444](https://osv.dev/vulnerability/OSV-2023-444), JPEG 2000 decoding | **Not affected: component not present.** Exact scanner configuration, built archives, Java and ELF inventories exclude imgcodecs/OpenJPEG. |
| [OSV-2025-486](https://osv.dev/vulnerability/OSV-2025-486), [OSV-2025-525](https://osv.dev/vulnerability/OSV-2025-525), PNG decoder reports | **Not affected: component not present.** Those imgcodecs decoder paths are excluded on both supported ABIs. This does not assess Android's separate image decoders. |
| [CVE-2025-69277](https://00f.net/2025/12/30/libsodium-vulnerability/), Ed25519 point validation | **Fixed.** Official signature-verified libsodium 1.0.20 source receives exact upstream fix [ad3004e](https://github.com/jedisct1/libsodium/commit/ad3004ec8731730e93fcfbbc824e67eadc1c1bae). The original binary accepts the upstream mixed-order fixture; the patched one rejects it on API 26/API 35. SecretBox ciphertext is identical and three upstream crypto regressions pass on each API. No password policy or encryption format changes. |

Both Android OpenCV versions pass the same 672 output-compatibility checks on
each API; these unsanitized runs do not negate the original host sanitizer
failure. Both backports retain their original JNI/public export sets, API 26
minimum, 16-KiB load alignment and path privacy. Scanner Java/resources/models,
notices and original packaged `libc++_shared.so` remain byte-identical. Unused
32-bit libsodium binaries are omitted from the distinct local AAR so an unpatched
ABI cannot later enter the APK accidentally. The app already supports the two
64-bit ABIs only. Arm64 is cross-built and statically audited, not executed by
the x86_64 emulator checks.

The initial scan on 6 November returned all four OpenCV matches and retained the
known libsodium finding despite its empty OSV source-tag result. They are not
removed from future query output; the current review resolves their exact local
artifact builds. Published source tags alone cannot express these backports.

## Remaining coverage and future maintenance

- OpenCV source: [4.12.0 archive](https://github.com/opencv/opencv/archive/refs/tags/4.12.0.zip), SHA256 `fa3faf7581f1fa943c9e670cf57dd6ba1c5b4178f363a188a2c8bff1eb28b7e4`, plus the bundled typed-dispatch patch. Only core/imgproc/Java are built; static transitive coverage is not exhaustive.
- libsodium source: [1.0.20 release tarball](https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz), SHA256 `ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19`, plus the exact upstream patch. Source-tree admission rejects extra/missing/changed files and symlinks before compilation. Wrapper Java remains Lazysodium 5.2.0.
- NDK libc++: original scanner runtime retained, publisher evidence declares NDK 28.2.13676358. No verified OSV identity mapping; an NDK revision is not a libc++ upstream version.
- JNA 5.17.0/libffi: source declares vendored libffi 3.4.4, but its patch-level/binary attestation remains incomplete. Do not pretend this is the exact unmodified upstream tag.
- CameraX 1.4.2/libyuv: exact pinned AAR bytes are verified; the embedded libyuv revision remains unbound. Attribution URLs are not version proof.
- AndroidX graphics/datastore and ONNX Runtime: pinned bytes and mapped wrapper/source queries remain; transitive build/source coverage is incomplete.

Before a release or dependency upgrade, refresh queries, review newly observed
IDs and coverage gaps, verify the exact APK and preserve dated reports/R8 maps.
Version-bound Gradle substitutions select only the reviewed base dependencies;
a future upstream version does not inherit these backports automatically.
Retire the local forks only after an independently verified upstream replacement
and the relevant crypto/scanner regressions. Never regenerate native hashes or
resolution records merely to pass a mismatch. OCR remains disabled; no
Tesseract/Leptonica libraries occur in the expected APK set.
