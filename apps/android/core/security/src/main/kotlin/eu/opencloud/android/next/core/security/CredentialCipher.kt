package eu.opencloud.android.next.core.security

import android.util.Base64
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class CredentialPlaintext(
    val plaintext: String,
    val legacy: Boolean,
) {
    override fun toString(): String = "CredentialPlaintext([REDACTED])"
}

/** v2 authenticates the complete storage slot. Legacy ciphertext has no historic slot binding. */
internal class CredentialCipher(
    private val key: (Boolean) -> SecretKey?,
) {
    fun encrypt(
        slot: String,
        value: String,
        createIfMissing: Boolean = true,
    ): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, requireNotNull(key(createIfMissing)))
        cipher.updateAAD(associatedData(slot))
        return "v2:" +
            listOf(cipher.iv, cipher.doFinal(utf8(value)))
                .joinToString(":") { Base64.encodeToString(it, Base64.NO_WRAP) }
    }

    // Providers throw checked and runtime exceptions. Never attach an exception or plaintext to logs.
    @Suppress("TooGenericExceptionCaught")
    fun decrypt(
        slot: String,
        value: String,
    ): CredentialPlaintext? =
        try {
            require(value.length <= MAX_ENVELOPE_CHARS)
            val parts = value.split(':')
            val legacy = parts.size == 2
            require(legacy || (parts.size == 3 && parts[0] == "v2"))
            val iv = decodeBase64(parts[if (legacy) 0 else 1])
            val encrypted = decodeBase64(parts[if (legacy) 1 else 2])
            require(iv.size == 12 && encrypted.size >= 16)
            val secret = key(false)
            if (secret == null) {
                Log.w("CredentialStore", "Credential unavailable: missing_key")
                null
            } else {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
                if (!legacy) cipher.updateAAD(associatedData(slot))
                val plaintext =
                    StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(cipher.doFinal(encrypted)))
                        .toString()
                CredentialPlaintext(plaintext, legacy)
            }
        } catch (error: Exception) {
            Log.w("CredentialStore", "Credential unavailable: ${credentialFailureCategory(error)}")
            null
        }

    private fun utf8(value: String): ByteArray =
        StandardCharsets.UTF_8
            .newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(CharBuffer.wrap(value))
            .let { encoded -> ByteArray(encoded.remaining()).also(encoded::get) }

    private fun decodeBase64(value: String): ByteArray {
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        require(Base64.encodeToString(bytes, Base64.NO_WRAP) == value)
        return bytes
    }

    private fun associatedData(slot: String): ByteArray =
        ByteArrayOutputStream()
            .also { output ->
                DataOutputStream(output).use { data ->
                    listOf("app.raiun.cloud/secure_credentials", "2", slot).forEach { field ->
                        val bytes = utf8(field)
                        data.writeInt(bytes.size)
                        data.write(bytes)
                    }
                }
            }.toByteArray()

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"

        // A validated record has at most 64 Ki UTF-16 code units, each requiring at most three UTF-8 bytes.
        const val MAX_ENVELOPE_CHARS = 4 * 64 * 1024 + 64
    }
}
