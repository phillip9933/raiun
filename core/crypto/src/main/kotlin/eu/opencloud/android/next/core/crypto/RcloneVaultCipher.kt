package eu.opencloud.android.next.core.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.SecretBox
import org.bouncycastle.crypto.generators.SCrypt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/** The OpenCloud Web rclone-crypt profile (default salt, standard base32hex names). */
class RcloneVaultCipher private constructor(
    private val keys: ByteArray,
    private val secretBox: SecretBox.Native,
) : AutoCloseable {
    private var closed = false

    /** A defensive copy for local Keystore wrapping. The caller owns and must clear it. */
    @Synchronized fun exportKeyMaterial(): ByteArray {
        checkOpen()
        return keys.copyOf()
    }

    /** Creates the Web-compatible encrypted UUID stored in `ocrclone:integrity-id`. */
    @Synchronized fun createIntegrityToken(): String {
        checkOpen()
        val uuidBytes = UUID.randomUUID().toString().toByteArray(StandardCharsets.US_ASCII)
        val output = ByteArrayOutputStream(64)
        return try {
            encryptContent(ByteArrayInputStream(uuidBytes), output, uuidBytes.size.toLong())
            val ciphertext = output.toByteArray()
            try {
                Base64.getEncoder().encodeToString(ciphertext)
            } finally {
                ciphertext.fill(0)
            }
        } finally {
            uuidBytes.fill(0)
            output.reset()
        }
    }

    /** A single encrypted DAV path segment. Rejects names unsafe for local path use. */
    @Synchronized fun decryptName(encrypted: String): String {
        checkOpen()
        require(encrypted.isNotEmpty() && encrypted.length <= 3277) { "Invalid encrypted name length" }
        val raw = Base32Hex.decode(encrypted)
        require(raw.isNotEmpty() && raw.size % 16 == 0 && raw.size <= 2048) { "Invalid encrypted name size" }
        val padded = transformName(raw, false)
        try {
            val pad = padded.last().toInt() and 0xff
            require(pad in 1..16 && padded.size >= pad) { "Invalid name padding" }
            for (i in padded.size - pad until padded.size) {
                require(
                    (padded[i].toInt() and 0xff) == pad,
                ) { "Invalid name padding" }
            }
            val utf8 = padded.copyOfRange(0, padded.size - pad)
            try {
                val name =
                    try {
                        STRICT_UTF8.decode(ByteBuffer.wrap(utf8)).toString()
                    } catch (error: CharacterCodingException) {
                        throw IllegalArgumentException("Invalid UTF-8 vault name", error)
                    }
                return safeName(name)
            } finally {
                utf8.fill(0)
            }
        } finally {
            raw.fill(0)
            padded.fill(0)
        }
    }

    @Synchronized fun encryptName(plain: String): String {
        checkOpen()
        safeName(plain)
        val bytes = plain.toByteArray(StandardCharsets.UTF_8)
        val pad = 16 - (bytes.size % 16)
        val padded = ByteArray(bytes.size + pad)
        bytes.copyInto(padded)
        padded.fill(pad.toByte(), bytes.size)
        val encrypted = transformName(padded, true)
        try {
            return Base32Hex.encode(encrypted)
        } finally {
            bytes.fill(0)
            padded.fill(0)
            encrypted.fill(0)
        }
    }

    @Synchronized fun decryptPath(encrypted: String): String {
        checkOpen()
        if (encrypted.isEmpty()) return "" // The vault root is the empty relative path in Web.
        require(
            encrypted.length <= 32768 &&
                !encrypted.startsWith('/') &&
                !encrypted.endsWith('/'),
        ) { "Invalid path" }
        return encrypted.split('/').joinToString("/") { decryptName(it) }
    }

    @Synchronized fun encryptPath(plain: String): String {
        checkOpen()
        if (plain.isEmpty()) return ""
        require(plain.length <= 32768 && !plain.startsWith('/') && !plain.endsWith('/')) {
            "Invalid path"
        }
        return plain.split('/').joinToString("/") { encryptName(it) }
    }

    /** Authenticates each complete 64-KiB block before writing its plaintext. Does not close streams. */
    @Synchronized fun decryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long {
        checkOpen()
        require(maximumPlaintextBytes >= 0)
        val header = ByteArray(32)
        readExactly(input, header, header.size)
        require(header.copyOfRange(0, 8).contentEquals(MAGIC)) { "Invalid rclone file header" }
        val nonce = header.copyOfRange(8, 32)
        val block = ByteArray(65552)
        var total = 0L
        try {
            while (true) {
                val count = readUpTo(input, block)
                if (count == 0) return total
                require(count >= 16) { "Truncated encrypted block" }
                val plainSize = count - 16
                require(plainSize.toLong() <= maximumPlaintextBytes - total) { "Plaintext size limit exceeded" }
                val ciphertext = block.copyOf(count)
                val plain =
                    try {
                        openBlock(nonce, ciphertext)
                    } finally {
                        ciphertext.fill(0)
                    }
                try {
                    output.write(plain)
                    total += plain.size
                } finally {
                    plain.fill(0)
                }
                incrementNonce(nonce)
                if (count < block.size) return total
            }
        } finally {
            header.fill(0)
            nonce.fill(0)
            block.fill(0)
        }
    }

    /** Writes a fresh random file nonce. For deterministic fixtures, use the internal nonce overload. */
    @Synchronized fun encryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long {
        val nonce = ByteArray(24).also(SecureRandom()::nextBytes)
        try {
            return encryptContentWithNonce(input, output, maximumPlaintextBytes, nonce)
        } finally {
            nonce.fill(0)
        }
    }

    @Synchronized internal fun encryptContentWithNonce(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
        fileNonce: ByteArray,
    ): Long {
        checkOpen()
        require(maximumPlaintextBytes >= 0 && fileNonce.size == 24)
        val nonce = fileNonce.copyOf()
        val plain = ByteArray(65536)
        var total = 0L
        output.write(MAGIC)
        output.write(nonce)
        try {
            while (true) {
                val count = readUpTo(input, plain)
                if (count == 0) return total
                require(count.toLong() <= maximumPlaintextBytes - total) { "Plaintext size limit exceeded" }
                val chunk = plain.copyOf(count)
                val ciphertext =
                    try {
                        sealBlock(nonce, chunk)
                    } finally {
                        chunk.fill(0)
                    }
                try {
                    output.write(ciphertext)
                } finally {
                    ciphertext.fill(0)
                }
                total += count
                incrementNonce(nonce)
                if (count < plain.size) return total
            }
        } finally {
            nonce.fill(0)
            plain.fill(0)
        }
    }

    /** Only an authenticated nonempty canonical UUID proves possession of the content key. */
    @Synchronized fun verifyIntegrityToken(base64Token: String): Boolean {
        checkOpen()
        val ciphertext =
            try {
                if (base64Token.isEmpty() || base64Token.length > 256) null else Base64.getDecoder().decode(base64Token)
            } catch (_: IllegalArgumentException) {
                null
            }
        return if (ciphertext == null) {
            false
        } else {
            try {
                if (ciphertext.size !in 49..256) {
                    false
                } else {
                    val plaintext = ByteArrayOutputStream(64)
                    val count = decryptContent(ByteArrayInputStream(ciphertext), plaintext, 64)
                    count == 36L && UUID_PATTERN.matches(plaintext.toString(StandardCharsets.US_ASCII.name()))
                }
            } catch (_: IllegalArgumentException) {
                false
            } catch (_: SecurityException) {
                false
            } catch (_: IOException) {
                false
            } finally {
                ciphertext.fill(0)
            }
        }
    }

    @Synchronized override fun close() {
        keys.fill(0)
        closed = true
    }

    private fun checkOpen() = check(!closed) { "Vault cipher is closed" }

    private fun transformName(
        input: ByteArray,
        encrypt: Boolean,
    ): ByteArray {
        val key = keys.copyOfRange(32, 64)
        val tweak = keys.copyOfRange(64, 80)
        return try {
            Eme.transform(key, tweak, input, encrypt)
        } finally {
            key.fill(0)
            tweak.fill(0)
        }
    }

    private fun sealBlock(
        nonce: ByteArray,
        plain: ByteArray,
    ): ByteArray {
        val key = keys.copyOfRange(0, 32)
        return try {
            val ciphertext = ByteArray(plain.size + 16)
            check(secretBox.cryptoSecretBoxEasy(ciphertext, plain, plain.size.toLong(), nonce, key)) {
                "libsodium SecretBox encryption failed"
            }
            ciphertext
        } finally {
            key.fill(0)
        }
    }

    private fun openBlock(
        nonce: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val key = keys.copyOfRange(0, 32)
        val plain = ByteArray(ciphertext.size - 16)
        return try {
            if (!secretBox.cryptoSecretBoxOpenEasy(plain, ciphertext, ciphertext.size.toLong(), nonce, key)) {
                plain.fill(0)
                throw SecurityException("Encrypted block authentication failed")
            }
            plain
        } finally {
            key.fill(0)
        }
    }

    companion object {
        private val MAGIC = byteArrayOf(82, 67, 76, 79, 78, 69, 0, 0)
        private val SALT =
            byteArrayOf(
                0xa8.toByte(),
                0x0d,
                0xf4.toByte(),
                0x3a,
                0x8f.toByte(),
                0xbd.toByte(),
                0x03,
                0x08,
                0xa7.toByte(),
                0xca.toByte(),
                0xb8.toByte(),
                0x3e,
                0x58,
                0x1f,
                0x86.toByte(),
                0xb1.toByte(),
            )
        private val UUID_PATTERN = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        private val STRICT_UTF8 get() =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)

        private val androidSecretBox: SecretBox.Native by lazy { LazySodiumAndroid(SodiumAndroid()) }

        fun fromPassword(password: CharArray): RcloneVaultCipher = fromPasswordWithSecretBox(password, androidSecretBox)

        internal fun fromPasswordWithSecretBox(
            password: CharArray,
            secretBox: SecretBox.Native,
        ): RcloneVaultCipher {
            require(password.isNotEmpty()) { "Vault password must not be empty" }
            val encoded =
                StandardCharsets.UTF_8
                    .newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(password))
            val passwordBytes = ByteArray(encoded.remaining())
            encoded.get(passwordBytes)
            if (encoded.hasArray()) encoded.array().fill(0)
            try {
                val derived = SCrypt.generate(passwordBytes, SALT, 16384, 8, 1, 80)
                return try {
                    fromKeyMaterialWithSecretBox(derived, secretBox)
                } finally {
                    derived.fill(0)
                }
            } finally {
                passwordBytes.fill(0)
            }
        }

        /** Restores the 80-byte key bundle after authenticated local Keystore unwrap. */
        fun fromKeyMaterial(material: ByteArray): RcloneVaultCipher =
            fromKeyMaterialWithSecretBox(material, androidSecretBox)

        internal fun fromKeyMaterialWithSecretBox(
            material: ByteArray,
            secretBox: SecretBox.Native,
        ): RcloneVaultCipher {
            require(material.size == 80) { "Invalid rclone key bundle" }
            return RcloneVaultCipher(material.copyOf(), secretBox)
        }

        private fun safeName(name: String): String {
            require(
                name.isNotEmpty() && name != "." && name != ".." && name != "/" && name != "\\",
            ) { "Unsafe vault name" }
            require(!name.contains('/') && !name.contains('\\') && !name.contains('\u0000')) { "Unsafe vault name" }
            require(name.none { Character.isISOControl(it) }) { "Unsafe vault name" }
            val encoded =
                try {
                    StandardCharsets.UTF_8
                        .newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .encode(CharBuffer.wrap(name))
                } catch (error: CharacterCodingException) {
                    throw IllegalArgumentException("Invalid UTF-8 vault name", error)
                }
            require(encoded.remaining() <= 255) { "Vault name is too long" }
            return name
        }

        private fun readExactly(
            input: InputStream,
            dst: ByteArray,
            length: Int,
        ) {
            var at = 0
            while (at < length) {
                val n = input.read(dst, at, length - at)
                if (n < 0) throw IOException("Truncated rclone file header")
                if (n == 0) {
                    val byte = input.read()
                    if (byte < 0) throw IOException("Truncated rclone file header")
                    dst[at++] = byte.toByte()
                    continue
                }
                at += n
            }
        }

        private fun readUpTo(
            input: InputStream,
            dst: ByteArray,
        ): Int {
            var at = 0
            var eof = false
            while (at < dst.size && !eof) {
                val n = input.read(dst, at, dst.size - at)
                if (n < 0) {
                    eof = true
                } else if (n == 0) {
                    val byte = input.read()
                    if (byte < 0) {
                        eof = true
                    } else {
                        dst[at++] = byte.toByte()
                    }
                } else {
                    at += n
                }
            }
            return at
        }

        private fun incrementNonce(nonce: ByteArray) {
            var carry = true
            for (i in nonce.indices) {
                if (carry) {
                    nonce[i] = (nonce[i] + 1).toByte()
                    carry = nonce[i].toInt() == 0
                }
            }
            check(!carry) { "Rclone nonce exhausted" }
        }
    }
}

private object Base32Hex {
    private const val ALPHABET = "0123456789abcdefghijklmnopqrstuv"

    fun encode(bytes: ByteArray): String {
        val result = StringBuilder((bytes.size * 8 + 4) / 5)
        var bits = 0
        var value = 0
        for (byte in bytes) {
            value = (value shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                result.append(ALPHABET[(value ushr bits) and 31])
            }
        }
        if (bits > 0) result.append(ALPHABET[(value shl (5 - bits)) and 31])
        return result.toString()
    }

    fun decode(text: String): ByteArray {
        require(text.isNotEmpty() && text.none { it == '=' }) { "Invalid base32hex name" }
        val output = ByteArrayOutputStream(text.length * 5 / 8)
        var bits = 0
        var value = 0
        for (char in text) {
            val ascii = if (char in 'A'..'V') (char.code + 32).toChar() else char
            val digit = ALPHABET.indexOf(ascii)
            require(digit >= 0) { "Invalid base32hex name" }
            value = (value shl 5) or digit
            bits += 5
            if (bits >= 8) {
                bits -= 8
                output.write((value ushr bits) and 0xff)
            }
        }
        require(bits < 5 && (value and ((1 shl bits) - 1)) == 0) { "Invalid base32hex padding bits" }
        return output.toByteArray()
    }
}
