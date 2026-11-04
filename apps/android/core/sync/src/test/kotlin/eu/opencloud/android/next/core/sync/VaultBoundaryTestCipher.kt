package eu.opencloud.android.next.core.sync

import okio.ByteString.Companion.encodeUtf8
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/** Synthetic block cipher deliberately holds the same stream monitor as the native Rclone implementation. */
internal class VaultBoundaryTestCipher(
    private val onName: ((String) -> Unit)? = null,
) : VaultCipherEngine {
    val closed = AtomicBoolean(false)
    val forks = java.util.concurrent.CopyOnWriteArrayList<VaultBoundaryTestCipher>()
    var refuseFork = false

    override fun forkForContent(): VaultCipherEngine {
        if (refuseFork) {
            throw eu.opencloud.android.next.core.network.OpenCloudException(
                eu.opencloud.android.next.core.network.OpenCloudError.Unsupported,
            )
        }
        return VaultBoundaryTestCipher().also(forks::add)
    }

    override fun createIntegrityToken() = "proof-token"

    override fun verifyIntegrityToken(base64Token: String) = base64Token == "proof-token"

    @Synchronized override fun encryptName(plain: String) =
        "enc_" + Base64.getUrlEncoder().withoutPadding().encodeToString(plain.encodeUtf8().toByteArray())

    @Synchronized override fun decryptName(encrypted: String): String {
        onName?.invoke(encrypted)
        return String(Base64.getUrlDecoder().decode(encrypted.removePrefix("enc_")))
    }

    @Synchronized override fun encryptPath(plain: String) =
        if (plain.isEmpty()) {
            ""
        } else {
            plain.split('/').joinToString("/") {
                encryptName(it)
            }
        }

    @Synchronized override fun decryptPath(encrypted: String) =
        if (encrypted.isEmpty()) {
            ""
        } else {
            encrypted.split('/').joinToString("/") {
                decryptName(it)
            }
        }

    @Synchronized override fun encryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long {
        output.write(ByteArray(32) { 7 })
        val block = ByteArray(65536)
        var total = 0L
        try {
            while (true) {
                val count = readBlock(input, block)
                if (count == 0) return total
                require(count.toLong() <= maximumPlaintextBytes - total)
                for (index in 0 until count) block[index] = (block[index].toInt() xor 0x5a).toByte()
                output.write(block, 0, count)
                output.write(ByteArray(16) { 9 })
                total += count
                if (count < block.size) return total
            }
        } finally {
            block.fill(0)
        }
    }

    fun encryptBytes(plaintext: ByteArray): ByteArray =
        ByteArrayOutputStream()
            .also {
                encryptContent(ByteArrayInputStream(plaintext), it, plaintext.size.toLong())
            }.toByteArray()

    @Synchronized override fun decryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long {
        val header = ByteArray(32)
        require(readBlock(input, header) == header.size && header.all { it == 7.toByte() })
        val block = ByteArray(65552)
        var total = 0L
        try {
            while (true) {
                val count = readBlock(input, block)
                if (count == 0) return total
                require(count >= 16 && block.sliceArray(count - 16 until count).all { it == 9.toByte() })
                val plainSize = count - 16
                require(plainSize.toLong() <= maximumPlaintextBytes - total)
                for (index in 0 until plainSize) block[index] = (block[index].toInt() xor 0x5a).toByte()
                output.write(block, 0, plainSize)
                total += plainSize
                if (count < block.size) return total
            }
        } finally {
            header.fill(0)
            block.fill(0)
        }
    }

    private fun readBlock(
        input: InputStream,
        block: ByteArray,
    ): Int {
        var count = 0
        while (count < block.size) {
            val read = input.read(block, count, block.size - count)
            if (read < 0) break
            if (read > 0) count += read
        }
        return count
    }

    @Synchronized override fun exportKeyMaterial() = ByteArray(80)

    override fun close() {
        closed.set(true)
    }
}
