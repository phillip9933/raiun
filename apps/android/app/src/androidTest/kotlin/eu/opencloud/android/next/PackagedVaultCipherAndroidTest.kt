package eu.opencloud.android.next

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.crypto.VaultContentIntegrityException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Exercises the Android JNA/libsodium path in the installed app, using only a public synthetic fixture.
 * Direct test linkage makes this cipher entry point reachable in the tested variant; it does not
 * independently prove retention of unreferenced production entry points or a complete vault journey.
 */
@RunWith(AndroidJUnit4::class)
class PackagedVaultCipherAndroidTest {
    @Test fun packagedNativeSecretBoxDecryptsKnownAnswerAndRejectsTamperingBeforePlaintext() {
        // The same fixed zero-key, fixed-nonce rclone fixture used by the core:crypto native test.
        val ciphertext =
            "52434c4f4e4500000102030405060708090a0b0c0d0e0f101112131415161718" +
                "095b446cd6237bbcb08d09fb524ce565aa"
        val bytes = ciphertext.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        RcloneVaultCipher.fromKeyMaterial(ByteArray(80)).use { cipher ->
            val plain = ByteArrayOutputStream()
            assertEquals(1L, cipher.decryptContent(ByteArrayInputStream(bytes), plain, 1))
            assertArrayEquals(byteArrayOf(1), plain.toByteArray())

            val tampered = bytes.copyOf()
            tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
            val rejectedPlaintext = ByteArrayOutputStream()
            assertThrows(VaultContentIntegrityException::class.java) {
                cipher.decryptContent(ByteArrayInputStream(tampered), rejectedPlaintext, 1)
            }
            assertEquals("An unauthenticated block must publish no plaintext", 0, rejectedPlaintext.size())
        }
    }
}
