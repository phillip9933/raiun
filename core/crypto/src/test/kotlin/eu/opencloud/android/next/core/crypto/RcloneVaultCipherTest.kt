package eu.opencloud.android.next.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64

class RcloneVaultCipherTest {
    private val hostSecretBox by lazy { LazySodiumJava(SodiumJava()) }

    private fun fromPassword(password: String) =
        RcloneVaultCipher.fromPasswordWithSecretBox(password.toCharArray(), hostSecretBox)

    private fun fromKeyMaterial(material: ByteArray) =
        RcloneVaultCipher.fromKeyMaterialWithSecretBox(material, hostSecretBox)

    // Key and name vectors from reference/rclone/backend/crypt/cipher_test.go.
    @Test fun rcloneKeyDerivationAndLifecycle() {
        val cipher = fromPassword("potato")
        val expected =
            hex(
                "7455c71ab17c865b8471f47b79acb07eb31d5678b80c7e2eaf4fc8066a9ee468" +
                    "765da27ab15d77f95796711f7b93ad63bbb484072e7180a8d17a9bbec14270d0" +
                    "c18d5932f55b2828c5e1e87215520310",
            )
        val exported = cipher.exportKeyMaterial()
        assertArrayEquals(expected, exported)
        exported.fill(0)
        assertArrayEquals(expected, cipher.exportKeyMaterial())
        val restored = fromKeyMaterial(expected)
        assertArrayEquals(expected, restored.exportKeyMaterial())
        cipher.close()
        assertThrows(IllegalStateException::class.java) { cipher.exportKeyMaterial() }
        restored.close()
    }

    @Test fun rcloneNamesAndPathValidation() {
        val zero = fromKeyMaterial(ByteArray(80))
        val names =
            listOf(
                "1" to "p0e52nreeaj0a5ea7s64m4j72s",
                "123456789012345" to "eeam3li4rnommi3a762h5n7meg",
                "1234567890123456" to "mijbj0frqf6ms7frcr6bd9h0env53jv96pjaaoirk7forcgpt70g",
            )
        for ((plain, encrypted) in names) {
            assertEquals(encrypted, zero.encryptName(plain))
            assertEquals(plain, zero.decryptName(encrypted.uppercase()))
        }
        assertEquals("1/123456789012345", zero.decryptPath(names[0].second + "/" + names[1].second))
        assertEquals("", zero.decryptPath(""))
        assertEquals("", zero.encryptPath(""))
        assertEquals("写真🗃️", zero.decryptName(zero.encryptName("写真🗃️")))
        for (unsafe in listOf("", ".", "..", "a/b", "a\\b", "a\u0000b")) {
            assertThrows(IllegalArgumentException::class.java) { zero.encryptName(unsafe) }
        }
        assertThrows(IllegalArgumentException::class.java) { zero.encryptName("\uD800") }
        assertThrows(IllegalArgumentException::class.java) { zero.encryptName("a\u0085b") }
        for (invalid in listOf("!", "p0e52nreeaj0a5ea7s64m4j72s=", "a/", "/a", "a//b")) {
            assertThrows(IllegalArgumentException::class.java) { zero.decryptPath(invalid) }
        }
        zero.close()
    }

    @Test fun rcloneFileVectorsAndAuthenticatedBoundaries() {
        val zero = fromKeyMaterial(ByteArray(80))
        val nonce = ByteArray(24) { (it + 1).toByte() }
        val expectedOne =
            hex(
                "52434c4f4e4500000102030405060708090a0b0c0d0e0f101112131415161718" +
                    "095b446cd6237bbcb08d09fb524ce565aa",
            )
        // SHA-256 of full blobs independently sealed with system libsodium 1.0.22.
        // Plaintext byte i = (31*i + 7) mod 256; nonce is 01..18, zero key.
        val sodiumHashes =
            mapOf(
                0 to "c77033388300949b8ef061845548d9c318ea0897176091ecbde4863478a4b2bc",
                1 to "26db981e5a19bfc6dacbd9dd4f0c13d355fba068bb15b941cb20fad68e72e297",
                65535 to "e5ac1ba93cd3090622c1f4f0b2cf753eb330b451480e2795f732fb605fde584d",
                65536 to "2255aab7defed76397cd5ca461638a1ba650927fb1447db5072156c1af2748c6",
                65537 to "12297a6b7b2a6bae42b2ae73ce4ec4dcb44a7bd115c106320fb1eb4857ca9356",
            )
        val one = ByteArrayOutputStream()
        zero.encryptContentWithNonce(ByteArrayInputStream(byteArrayOf(1)), one, 1, nonce)
        assertArrayEquals(expectedOne, one.toByteArray())
        val wrongKey = fromPassword("potato")
        assertThrows(SecurityException::class.java) {
            wrongKey.decryptContent(ByteArrayInputStream(expectedOne), ByteArrayOutputStream(), 1)
        }
        wrongKey.close()
        val badHeader = expectedOne.copyOf()
        badHeader[0] = 0
        assertThrows(IllegalArgumentException::class.java) {
            zero.decryptContent(ByteArrayInputStream(badHeader), ByteArrayOutputStream(), 1)
        }
        val badCiphertext = expectedOne.copyOf()
        badCiphertext[48] = (badCiphertext[48].toInt() xor 1).toByte()
        assertThrows(SecurityException::class.java) {
            zero.decryptContent(ByteArrayInputStream(badCiphertext), ByteArrayOutputStream(), 1)
        }

        for (size in listOf(0, 1, 65535, 65536, 65537)) {
            val plain = ByteArray(size) { (it * 31 + 7).toByte() }
            val encrypted = ByteArrayOutputStream()
            assertEquals(
                size.toLong(),
                zero.encryptContentWithNonce(ByteArrayInputStream(plain), encrypted, size.toLong(), nonce),
            )
            val bytes = encrypted.toByteArray()
            assertEquals(32 + size + 16 * ((size + 65535) / 65536), bytes.size)
            assertEquals(
                sodiumHashes[size],
                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                    "%02x".format(it)
                },
            )
            val decrypted = ByteArrayOutputStream()
            assertEquals(size.toLong(), zero.decryptContent(ByteArrayInputStream(bytes), decrypted, size.toLong()))
            assertArrayEquals(plain, decrypted.toByteArray())
            if (size > 0) {
                bytes[32] = (bytes[32].toInt() xor 1).toByte()
                assertThrows(SecurityException::class.java) {
                    zero.decryptContent(ByteArrayInputStream(bytes), ByteArrayOutputStream(), size.toLong())
                }
            }
        }
        zero.close()
    }

    @Test fun integrityTokenNeedsAuthenticatedUuid() {
        val zero = fromKeyMaterial(ByteArray(80))
        val nonce = ByteArray(24)
        val uuid = "123e4567-e89b-12d3-a456-426614174000".toByteArray()

        fun token(bytes: ByteArray): String {
            val output = ByteArrayOutputStream()
            zero.encryptContentWithNonce(ByteArrayInputStream(bytes), output, 64, nonce)
            return Base64.getEncoder().encodeToString(output.toByteArray())
        }
        assertTrue(zero.verifyIntegrityToken(token(uuid)))
        assertFalse(zero.verifyIntegrityToken(token(ByteArray(0))))
        assertFalse(zero.verifyIntegrityToken(token("not-a-uuid".toByteArray())))
        assertFalse(zero.verifyIntegrityToken("invalid"))
        zero.close()
    }

    @Test fun pinnedWebV8VectorsBothDirections() {
        // Generated by interop/web-oracle.mts from @fyears/rclone-crypt 0.0.7.
        val names =
            listOf(
                "1" to "9cmn80lns8obm4t3koceogil20",
                "123456789012345" to "39pfuflp0u10iqi88m20aq3i28",
                "1234567890123456" to "9qg6n1iouahpupqlekm1k6sa5psf32kr83f3vv36c5kqrhij022g",
                "12345678901234567" to "q954vaqdql2tkn1g9g546an1oo9npnm6m8vk4ausf4cq5i364jig",
                "写真🗃️" to "m9t62nq5a92ncslf90dorqurss",
                "folder/école.txt" to "um9jr7t436jbmsgpub5sfni4qk/ap8un5letkkhetgjpn9528qi4c",
            )
        val outputDirectory = System.getenv("RAIUN_CRYPTO_INTEROP_OUTPUT")?.let { Path.of(it) }
        outputDirectory?.let { Files.createDirectories(it) }
        fromPassword("potato").use { cipher ->
            val webToken =
                requireNotNull(javaClass.getResourceAsStream("/oracles/web-v8/web-integrity-token.b64"))
                    .bufferedReader()
                    .use { it.readText().trim() }
            assertTrue(cipher.verifyIntegrityToken(webToken))
            for ((index, pair) in names.withIndex()) {
                val (plain, encrypted) = pair
                assertEquals(encrypted, cipher.encryptPath(plain))
                assertEquals(plain, cipher.decryptPath(encrypted))
                outputDirectory?.let {
                    Files.write(
                        it.resolve("codec-name-$index.txt"),
                        cipher.encryptPath(plain).toByteArray(Charsets.UTF_8),
                    )
                }
            }
            val nonce = ByteArray(24) { (it + 1).toByte() }
            for (size in listOf(0, 1, 65535, 65536, 65537)) {
                val plain = ByteArray(size) { (it * 31 + 7).toByte() }
                val webCiphertext =
                    requireNotNull(javaClass.getResourceAsStream("/oracles/web-v8/web-$size.bin"))
                        .use { it.readBytes() }
                val decrypted = ByteArrayOutputStream()
                assertEquals(
                    size.toLong(),
                    cipher.decryptContent(ByteArrayInputStream(webCiphertext), decrypted, size.toLong()),
                )
                assertArrayEquals(plain, decrypted.toByteArray())
                val codecCiphertext = ByteArrayOutputStream()
                cipher.encryptContentWithNonce(ByteArrayInputStream(plain), codecCiphertext, size.toLong(), nonce)
                assertArrayEquals(webCiphertext, codecCiphertext.toByteArray())
                outputDirectory?.let { Files.write(it.resolve("codec-$size.bin"), codecCiphertext.toByteArray()) }
            }
        }
    }

    @Test fun rcloneV1751ProducedCiphertextAndNames() {
        // Official rclone v1.75.1 copyto output, with random nonces, from synthetic local files.
        val encryptedPaths =
            mapOf(
                0 to "f5qevq76he1rhpr8cjg4vbit6k/rpqc8vklnnj5nqtnhed844e6pqj5atv49gsh2holg2non2j2med0",
                1 to "f5qevq76he1rhpr8cjg4vbit6k/90pobgsfankmaqmn5mnk1g2q1euj0jdhvp4ftq6kvmm8l4uhll2g",
                65535 to "f5qevq76he1rhpr8cjg4vbit6k/iitm83ecv3ls4i737ls5pmgd08e5l9r04e12gu7qgg4rqnphceb0",
                65536 to "f5qevq76he1rhpr8cjg4vbit6k/br50ui52emjgajulgft36qvc7tf4ke7qa7dkvmlnfo4lu5uvn4qg",
                65537 to "f5qevq76he1rhpr8cjg4vbit6k/1sjbdv65fk0ih90u44je3u9oo548bi5ppg9q023n6aklqemohseg",
            )
        fromPassword("potato").use { cipher ->
            for ((size, encryptedPath) in encryptedPaths) {
                assertEquals("interop/写真🗃️-$size.bin", cipher.decryptPath(encryptedPath))
                assertEquals(encryptedPath, cipher.encryptPath("interop/写真🗃️-$size.bin"))
                val encrypted =
                    requireNotNull(javaClass.getResourceAsStream("/oracles/rclone-v1.75.1/rclone-$size.bin"))
                        .use { it.readBytes() }
                val decrypted = ByteArrayOutputStream()
                assertEquals(
                    size.toLong(),
                    cipher.decryptContent(ByteArrayInputStream(encrypted), decrypted, size.toLong()),
                )
                assertArrayEquals(ByteArray(size) { (it * 31 + 7).toByte() }, decrypted.toByteArray())
            }
        }
    }

    private fun hex(input: String): ByteArray = input.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
