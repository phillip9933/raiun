package eu.opencloud.android.next.core.sync

import java.io.InputStream
import java.io.OutputStream

/** Synthetic content authentication shared by offline store and directory regressions. */
internal class VaultOfflineTestCipher(
    private val onName: (() -> Unit)? = null,
) : VaultCipherEngine {
    override fun createIntegrityToken() = "proof"

    override fun verifyIntegrityToken(base64Token: String) = true

    override fun decryptName(encrypted: String): String {
        onName?.invoke()
        return encrypted
    }

    override fun decryptPath(encrypted: String) = encrypted

    override fun encryptName(plain: String) = plain

    override fun encryptPath(plain: String) = plain

    override fun encryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long = 0L

    override fun decryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long {
        val bytes = input.readBytes()
        require(
            bytes.size >= 48 &&
                bytes.take(32).all { it == 7.toByte() } &&
                bytes.takeLast(16).all { it == 9.toByte() },
        )
        val plain = bytes.copyOfRange(32, bytes.size - 16)
        require(plain.size.toLong() <= maximumPlaintextBytes)
        output.write(plain)
        val size = plain.size.toLong()
        plain.fill(0)
        bytes.fill(0)
        return size
    }

    override fun exportKeyMaterial() = ByteArray(80)

    override fun close() = Unit
}
