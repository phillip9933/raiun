package eu.opencloud.android.next.core.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/** Exercises Android's actual libsodium and JNA loading, not the host JVM backend. */
@RunWith(AndroidJUnit4::class)
class RcloneVaultCipherAndroidTest {
    @Test fun nativeSecretBoxDecryptsRcloneKnownAnswer() {
        val ciphertext =
            "52434c4f4e4500000102030405060708090a0b0c0d0e0f101112131415161718" +
                "095b446cd6237bbcb08d09fb524ce565aa"
        val bytes = ciphertext.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        RcloneVaultCipher.fromKeyMaterial(ByteArray(80)).use { cipher ->
            val plain = ByteArrayOutputStream()
            assertEquals(1L, cipher.decryptContent(ByteArrayInputStream(bytes), plain, 1))
            assertArrayEquals(byteArrayOf(1), plain.toByteArray())
            bytes[48] = (bytes[48].toInt() xor 1).toByte()
            assertThrows(SecurityException::class.java) {
                cipher.decryptContent(ByteArrayInputStream(bytes), ByteArrayOutputStream(), 1)
            }
        }
    }
}
