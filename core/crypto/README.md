# Rclone vault codec

This module implements the OpenCloud Web v8.0.0 rclone-crypt profile: scrypt
`N=16384, r=8, p=1` with rclone's built-in salt, 80 derived key bytes, AES-256
EME names in unpadded base32hex, and `RCLONE\0\0` files containing 64-KiB
XSalsa20-Poly1305 blocks. It accepts only that profile. Callers must verify a
nonempty authenticated UUID integrity token before treating a key as proven.
Decryption authenticates each block before writing that block; a caller must
discard partial output if a later block fails. The format does not authenticate
final file length, file path, or a whole-file version.

The production SecretBox implementation is Lazysodium Android 5.2.0, containing
libsodium 1.0.20, through the Android JNA 5.17.0 AAR. This replaces the earlier
archived `com.codahale:xsalsa20poly1305` candidate; no archived SecretBox code
ships. The JVM unit tests inject Lazysodium Java against host libsodium. AES and
scrypt use Bouncy Castle `bcprov-jdk18on` 1.81. The EME transform adapts
[`rfjakob/eme` v1.2.0](https://github.com/rfjakob/eme/tree/v1.2.0), copyright
(c) 2015 Jakob Unterwurzacher. Bundled license texts and provenance are in
[`src/main/assets/third-party/vault-crypto/NOTICE.md`](src/main/assets/third-party/vault-crypto/NOTICE.md).

The shipped native ABIs are arm64-v8a and x86_64. The Lazysodium 5.2.0 AAR
(SHA-256 `b5378c1d9db2573d61b304e89cf83db187a05c3e4ff081d9b2ef3d0bb00ca314`)
and JNA Android 5.17.0 AAR
(SHA-256 `4dbeffffa665d97ad5aa7eee297531d3c841a86716ab7f774fd6956422b3cf38`)
were inspected with `readelf -lW`: every PT_LOAD segment in their arm64-v8a and
x86_64 `libsodium.so` and `libjnidispatch.so` has `p_align=0x4000` (16 KiB).
An API 35 emulator instrumentation test loaded the production Android backend
and decrypted a known rclone vector, then rejected modified ciphertext.

Interoperability oracles use only synthetic password `potato` and plaintext
byte `i = (31*i + 7) mod 256` at lengths 0, 1, 65,535, 65,536, and 65,537.
The fixed nonce for Web and codec generation is bytes `01..18` hex. The five
rclone-generated fixtures use rclone's own random nonces.

- `@fyears/rclone-crypt` 0.0.7 from the checked-out OpenCloud Web v8.0.0 source
  at `fe7ce657bcf92566986ed1572f90e1cbb4683464` produced
  [`oracles/web-v8`](src/test/resources/oracles/web-v8) with its pinned
  `@fyears/eme` 0.0.3, `@noble/ciphers` 0.5.3, and `@noble/hashes` 1.8.0.
  [`interop/web-oracle.mts`](interop/web-oracle.mts) generated and verified
  both directions: Web files and six names, including Unicode and a path,
  decrypt in the codec; codec files and names decrypt in Web. The Web UUID
  token also authenticates in the codec.
- Official rclone Linux amd64 v1.75.1 binary, release commit `687d264`,
  downloaded from `https://downloads.rclone.org/v1.75.1/rclone-v1.75.1-linux-amd64.zip`
  (ZIP SHA-256 `982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab`),
  produced [`oracles/rclone-v1.75.1`](src/test/resources/oracles/rclone-v1.75.1)
  using `copyto` into a standard filename/directory encryption crypt remote.
  The codec decrypts all five ciphertexts and their Unicode paths. The binary
  also decrypted codec-generated ciphertext at all five lengths with `cat`
  and decoded Web Unicode names with `cryptdecode`.
- The 80-byte `potato` key bundle, zero-key names, and one-byte file vector
  come from the separately checked-out
  [`rclone/backend/crypt/cipher_test.go`](https://github.com/rclone/rclone/blob/a82c965ba1a248a726f739d033e4c0d42543c2e4/backend/crypt/cipher_test.go)
  at `a82c965ba1a248a726f739d033e4c0d42543c2e4`. This checkout is newer
  than the official v1.75.1 binary used for the executable oracle.
- Complete-file SHA-256 values from system libsodium 1.0.22 independently
  cover the five lengths and nonce increment with a zero key. Tests also
  reject wrong keys, modified headers/tags/ciphertext, unsafe names and paths,
  and header-only integrity tokens.

The focused module JVM tests, ktlint, and detekt checks passed, as did the
Android API 35 emulator instrumentation test. This codec has no production
vault UI integration by itself. End-to-end vault discovery, unlock, and remote
content behavior must be validated with the application before release.
