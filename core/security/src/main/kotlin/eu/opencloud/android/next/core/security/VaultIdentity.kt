package eu.opencloud.android.next.core.security

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Stable remote scope for a remembered vault key. The server value must already be canonical. */
data class VaultIdentity(
    val accountId: String,
    val canonicalServer: String,
    val driveId: String,
    val remoteVaultId: String,
) {
    private val encodedValue: ByteArray by lazy(LazyThreadSafetyMode.PUBLICATION) {
        encodeIdentity(accountId, canonicalServer, driveId, remoteVaultId)
    }

    internal val encoded: ByteArray get() = encodedValue.copyOf()

    private val associatedDataValue: ByteArray by lazy(LazyThreadSafetyMode.PUBLICATION) {
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(AAD_MAGIC)
                output.writeInt(IDENTITY_VERSION)
                val profile = PROFILE.toByteArray(StandardCharsets.UTF_8)
                output.writeInt(profile.size)
                output.write(profile)
                output.writeInt(encodedValue.size)
                output.write(encodedValue)
            }
            bytes.toByteArray()
        }
    }

    internal val associatedData: ByteArray get() = associatedDataValue.copyOf()

    private fun encodeIdentity(vararg values: String): ByteArray {
        require(values.size == FIELD_COUNT)
        val encodedValues = values.map(::encodeField)
        require(encodedValues.sumOf { it.size } <= MAX_IDENTITY_BYTES) {
            "Vault identity is too large."
        }
        require(
            values.all { value ->
                value.isNotBlank() && value == value.trim() && value.none { it.isISOControl() }
            },
        ) {
            "Vault identity fields must be non-empty canonical values."
        }

        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(IDENTITY_VERSION)
                encodedValues.forEach { field ->
                    output.writeInt(field.size)
                    output.write(field)
                }
            }
            bytes.toByteArray()
        }
    }

    private fun encodeField(value: String): ByteArray {
        require(value.isNotEmpty()) { "Vault identity fields must be non-empty." }
        val buffer =
            StandardCharsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(java.nio.CharBuffer.wrap(value))
        require(buffer.remaining() <= MAX_FIELD_BYTES) { "Vault identity field is too large." }
        return ByteArray(buffer.remaining()).also(buffer::get)
    }

    companion object {
        private const val IDENTITY_VERSION = 1
        private const val FIELD_COUNT = 4
        private const val MAX_FIELD_BYTES = 4096
        private const val MAX_IDENTITY_BYTES = 16 * 1024
        private const val PROFILE = "opencloud-rclone-crypt-web-key-bundle-v1"
        private val AAD_MAGIC = byteArrayOf(0x52, 0x41, 0x49, 0x55, 0x4e, 0x56, 0x4b, 0x31) // RAIUNVK1
    }
}
