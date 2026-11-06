package eu.opencloud.android.next.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.SecretBox
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class RcloneVaultCipherCloseTest {
    private val sodium by lazy { LazySodiumJava(SodiumJava()) }
    private val nativeArguments = CopyOnWriteArrayList<List<ByteArray>>()

    private fun cipher(failNative: Boolean = false): RcloneVaultCipher {
        val recording =
            Proxy.newProxyInstance(
                SecretBox.Native::class.java.classLoader,
                arrayOf(SecretBox.Native::class.java),
            ) { _, method, arguments ->
                if (method.name == "cryptoSecretBoxEasy" || method.name == "cryptoSecretBoxOpenEasy") {
                    nativeArguments.add(requireNotNull(arguments).filterIsInstance<ByteArray>())
                    if (failNative) throw IOException("synthetic native failure")
                }
                try {
                    method.invoke(sodium, *(arguments ?: emptyArray()))
                } catch (error: InvocationTargetException) {
                    throw error.targetException
                }
            } as SecretBox.Native
        return RcloneVaultCipher.fromKeyMaterialWithSecretBox(ByteArray(80) { 42 }, recording)
    }

    @Test fun `close wipes keys without waiting for an uncooperative plaintext producer`() {
        val cipher = cipher()
        val input = StalledInput(byteArrayOf(1, 2, 3))
        val output = ByteArrayOutputStream()
        closeWhileBlocked(cipher, input.gate) {
            cipher.encryptContent(input, output, 3)
        }
        assertEquals(32, output.size())
        assertEquals(0, nativeArguments.size)
        assertWiped(requireNotNull(input.borrowed))
    }

    @Test fun `close during ciphertext header read prevents empty content success`() {
        val cipher = cipher()
        val header = ciphertext(ByteArray(0))
        nativeArguments.clear()
        val input = StalledInput(header)
        val output = ByteArrayOutputStream()
        closeWhileBlocked(cipher, input.gate) {
            cipher.decryptContent(input, output, 0)
        }
        assertEquals(0, output.size())
        assertEquals(0, nativeArguments.size)
        assertWiped(requireNotNull(input.borrowed))
    }

    @Test fun `close during EOF read rejects empty and exact block completion`() {
        for (size in listOf(0, 65536)) {
            val cipher = cipher()
            val input = StalledInput(ByteArray(size), stallAtEnd = true)
            val output = ByteArrayOutputStream()
            closeWhileBlocked(cipher, input.gate) {
                cipher.encryptContent(input, output, size.toLong())
            }
            assertEquals(32 + size + if (size == 0) 0 else 16, output.size())
            assertWiped(requireNotNull(input.borrowed))
        }
        val cipher = cipher()
        val input = StalledInput(ciphertext(ByteArray(0)), stallAtEnd = true)
        closeWhileBlocked(cipher, input.gate) {
            cipher.decryptContent(input, ByteArrayOutputStream(), 0)
        }
        assertWiped(requireNotNull(input.borrowed))
    }

    @Test fun `close does not wait for any external encryption write and forbids later blocks`() {
        for (write in 1..3) {
            nativeArguments.clear()
            val cipher = cipher()
            val output = StalledOutput(write)
            var readBuffer: ByteArray? = null
            val input =
                object : ByteArrayInputStream(ByteArray(65537) { 7 }) {
                    override fun read(
                        bytes: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int {
                        readBuffer = bytes
                        return super.read(bytes, offset, length)
                    }
                }
            closeWhileBlocked(cipher, output.gate, whileBlocked = { readBuffer?.let(::assertWiped) }) {
                cipher.encryptContent(input, output, 65537)
            }
            assertEquals(write, output.calls)
            if (write > 1) assertWiped(requireNotNull(output.borrowed))
            assertTrue(nativeArguments.size <= 1)
        }
    }

    @Test fun `close wipes keys while authenticated plaintext output is stalled`() {
        val encrypted = ciphertext(ByteArray(65537) { 7 })
        nativeArguments.clear()
        val cipher = cipher()
        val output = StalledOutput(1)
        closeWhileBlocked(cipher, output.gate) {
            cipher.decryptContent(encrypted.inputStream(), output, 65537)
        }
        assertEquals(1, nativeArguments.size)
        assertEquals(1, output.calls)
        assertWiped(requireNotNull(output.borrowed))
    }

    @Test fun `closed cipher rejects empty content before touching caller streams`() {
        val cipher = cipher()
        cipher.close()
        val input =
            object : InputStream() {
                override fun read(): Int = error("Closed operation read external input")
            }
        val output =
            object : OutputStream() {
                override fun write(value: Int): Unit = error("Closed operation wrote external output")
            }
        assertThrows(IllegalStateException::class.java) { cipher.encryptContent(input, output, 0) }
        assertThrows(IllegalStateException::class.java) { cipher.decryptContent(input, output, 0) }
        assertThrows(IllegalStateException::class.java) {
            cipher.encryptContentWithNonce(input, output, 0, ByteArray(24))
        }
    }

    @Test fun `failed header output clears copied nonce`() {
        cipher().use { cipher ->
            var nonce: ByteArray? = null
            val output =
                object : OutputStream() {
                    override fun write(value: Int) = Unit

                    override fun write(bytes: ByteArray) {
                        if (bytes.size == 24) {
                            nonce = bytes
                            throw IOException("synthetic output failure")
                        }
                    }
                }
            assertThrows(IOException::class.java) {
                cipher.encryptContentWithNonce(ByteArray(0).inputStream(), output, 0, ByteArray(24) { 7 })
            }
            assertWiped(requireNotNull(nonce))
        }
    }

    @Test fun `native failures clear key and partial native output and input chunks`() {
        val encrypted = ciphertext(byteArrayOf(1, 2, 3))
        for (encrypt in listOf(true, false)) {
            nativeArguments.clear()
            cipher(failNative = true).use { cipher ->
                // The proxy wraps a checked exception; callers only require that it cannot succeed.
                assertThrows(Exception::class.java) {
                    if (encrypt) {
                        cipher.encryptContent(byteArrayOf(1, 2, 3).inputStream(), ByteArrayOutputStream(), 3)
                    } else {
                        cipher.decryptContent(encrypted.inputStream(), ByteArrayOutputStream(), 3)
                    }
                }
            }
            assertEquals(1, nativeArguments.size)
            nativeArguments.single().forEach(::assertWiped)
        }
    }

    private fun ciphertext(plain: ByteArray): ByteArray =
        cipher().use { cipher ->
            ByteArrayOutputStream()
                .also {
                    cipher.encryptContent(
                        plain.inputStream(),
                        it,
                        plain.size.toLong(),
                    )
                }.toByteArray()
        }

    private fun closeWhileBlocked(
        cipher: RcloneVaultCipher,
        gate: Gate,
        whileBlocked: () -> Unit = {},
        operation: () -> Long,
    ) {
        val executor = Executors.newFixedThreadPool(2)
        val task =
            executor.submit<Throwable?> {
                try {
                    operation()
                    null
                } catch (error: Throwable) {
                    error
                }
            }
        try {
            assertTrue("External IO did not start", gate.entered.await(5, TimeUnit.SECONDS))
            executor.submit { cipher.close() }.get(1, TimeUnit.SECONDS)
            assertFalse("Noncooperative IO should still be stalled", task.isDone)
            assertThrows(IllegalStateException::class.java) { cipher.exportKeyMaterial() }
            val keys = RcloneVaultCipher::class.java.getDeclaredField("keys").also { it.isAccessible = true }
            assertWiped(keys.get(cipher) as ByteArray)
            // Native key copies must already be clear, before the external provider is released.
            nativeArguments.forEach { assertWiped(it.last()) }
            whileBlocked()
            gate.release.countDown()
            assertTrue(
                "A closed operation succeeded or failed for another reason",
                task.get(5, TimeUnit.SECONDS) is IllegalStateException,
            )
        } finally {
            gate.release.countDown()
            cipher.close()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    private fun assertWiped(bytes: ByteArray) =
        assertTrue("Temporary buffer was retained", bytes.all { it == 0.toByte() })

    private class Gate {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun await() {
            entered.countDown()
            assertTrue("Fixture release timed out", release.await(10, TimeUnit.SECONDS))
        }
    }

    private class StalledInput(
        bytes: ByteArray,
        private val stallAtEnd: Boolean = false,
    ) : ByteArrayInputStream(bytes) {
        val gate = Gate()
        var borrowed: ByteArray? = null
        private var stalled = false

        override fun read(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            borrowed = bytes
            if (!stalled && (!stallAtEnd || available() == 0)) {
                stalled = true
                gate.await()
            }
            return super.read(bytes, offset, length)
        }
    }

    private class StalledOutput(
        private val stallOnWrite: Int,
    ) : OutputStream() {
        val gate = Gate()
        var borrowed: ByteArray? = null
        var calls = 0

        override fun write(value: Int): Unit = error("Expected block writes")

        override fun write(bytes: ByteArray) {
            calls++
            if (calls == stallOnWrite) {
                borrowed = bytes
                gate.await()
            }
        }
    }
}
