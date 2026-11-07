package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.InputStream
import java.io.OutputStream

/** Narrow seam permits transport/session tests without loading Android's native Sodium binding. */
internal interface VaultCipherEngine : AutoCloseable {
    fun createIntegrityToken(): String

    fun verifyIntegrityToken(base64Token: String): Boolean

    fun decryptName(encrypted: String): String

    fun decryptPath(encrypted: String): String

    fun encryptName(plain: String): String

    fun encryptPath(plain: String): String

    fun encryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long

    fun decryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long

    fun exportKeyMaterial(): ByteArray

    /**
     * Only engines with an independent content cipher may support concurrent boundary pipes.
     * Creation performs memory-only key work; close must never wait on caller-owned stream IO.
     * The session revokes admitted forks on close and their owning operation's cancellation.
     */
    fun forkForContent(): VaultCipherEngine = throw OpenCloudException(OpenCloudError.Unsupported)
}

internal data class VaultCipherFactories(
    val password: (CharArray) -> VaultCipherEngine,
    val keyMaterial: (ByteArray) -> VaultCipherEngine,
)

internal fun RcloneVaultCipher.asVaultCipher(): VaultCipherEngine =
    object : VaultCipherEngine {
        override fun createIntegrityToken() = this@asVaultCipher.createIntegrityToken()

        override fun verifyIntegrityToken(base64Token: String) = this@asVaultCipher.verifyIntegrityToken(base64Token)

        override fun decryptName(encrypted: String) = this@asVaultCipher.decryptName(encrypted)

        override fun decryptPath(encrypted: String) = this@asVaultCipher.decryptPath(encrypted)

        override fun encryptName(plain: String) = this@asVaultCipher.encryptName(plain)

        override fun encryptPath(plain: String) = this@asVaultCipher.encryptPath(plain)

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = this@asVaultCipher.encryptContent(input, output, maximumPlaintextBytes)

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = authenticatedVaultContent { this@asVaultCipher.decryptContent(input, output, maximumPlaintextBytes) }

        override fun exportKeyMaterial() = this@asVaultCipher.exportKeyMaterial()

        override fun forkForContent(): VaultCipherEngine {
            val material = this@asVaultCipher.exportKeyMaterial()
            return try {
                RcloneVaultCipher.fromKeyMaterial(material).asVaultCipher()
            } finally {
                material.fill(0)
            }
        }

        override fun close() = this@asVaultCipher.close()
    }
