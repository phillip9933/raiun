package eu.opencloud.android.next.core.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Verifies the Android/native codec can revoke keys while a provider-like stream is blocked. */
@RunWith(AndroidJUnit4::class)
class VaultCipherCloseAndroidTest {
    @Test fun closeDoesNotWaitForAStalledEncryptionSource() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val read = AtomicBoolean(false)
        val source =
            object : InputStream() {
                override fun read(): Int {
                    if (!read.compareAndSet(false, true)) return -1
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS)) { "Synthetic source was not released" }
                    return 1
                }
            }
        assertRevokedBeforeIoReturns(entered, release) { cipher ->
            cipher.encryptContent(source, ByteArrayOutputStream(), 1)
        }
    }

    @Test fun closeDoesNotWaitForAStalledNativeDecryptionSink() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val plaintextBuffer = AtomicReference<ByteArray>()
        val sink =
            object : OutputStream() {
                override fun write(value: Int) = error("Block writes expected")

                override fun write(
                    bytes: ByteArray,
                    offset: Int,
                    length: Int,
                ) {
                    assertEquals(1, length)
                    assertEquals(1, bytes[offset].toInt())
                    plaintextBuffer.set(bytes)
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS)) { "Synthetic sink was not released" }
                }
            }
        val hex =
            "52434c4f4e4500000102030405060708090a0b0c0d0e0f101112131415161718" +
                "095b446cd6237bbcb08d09fb524ce565aa"
        val ciphertext = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertRevokedBeforeIoReturns(entered, release) { cipher ->
            cipher.decryptContent(ByteArrayInputStream(ciphertext), sink, 1)
        }
        assertTrue(requireNotNull(plaintextBuffer.get()).all { it == 0.toByte() })
    }

    private fun assertRevokedBeforeIoReturns(
        entered: CountDownLatch,
        release: CountDownLatch,
        operation: (RcloneVaultCipher) -> Long,
    ) {
        val threads = Executors.newFixedThreadPool(2)
        val cipher = RcloneVaultCipher.fromKeyMaterial(ByteArray(80))
        try {
            val transfer = threads.submit<Long> { operation(cipher) }
            assertTrue("Stream did not reach the controlled IO gate", entered.await(5, TimeUnit.SECONDS))
            val closing = threads.submit { cipher.close() }
            closing.get(5, TimeUnit.SECONDS)
            assertEquals("Close must finish before releasing external IO", 1L, release.count)
            assertThrows(IllegalStateException::class.java) { cipher.exportKeyMaterial() }
            release.countDown()
            val failure = assertThrows(ExecutionException::class.java) { transfer.get(5, TimeUnit.SECONDS) }
            assertTrue("A closed operation must reject late completion", failure.cause is IllegalStateException)
        } finally {
            release.countDown()
            threads.shutdownNow()
            assertTrue("Native fixture threads did not stop", threads.awaitTermination(5, TimeUnit.SECONDS))
            cipher.close()
        }
    }
}
