package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Versioned RVO2 framing, strict text and purpose-separated generation crypto. No keys persist. */
internal object VaultOfflineIndexCodec {
    private val random = SecureRandom()

    fun deriveIndexKey(
        material: ByteArray,
        identity: VaultIdentity,
        generation: String,
        purpose: String,
    ): ByteArray {
        validateIdentity(identity)
        val master = deriveManifestKey(material, identity)
        return try {
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(master, "HmacSHA256"))
                update("raiun-offline-index-v2-key\u0000".toByteArray(Charsets.US_ASCII))
                update(generation.toByteArray(Charsets.US_ASCII))
                update(0.toByte())
                doFinal(purpose.toByteArray(Charsets.US_ASCII))
            }
        } finally {
            master.fill(0)
        }
    }

    fun aad(
        identity: VaultIdentity,
        location: VaultLocation,
        generation: String,
        purpose: String,
        token: ByteArray = byteArrayOf(),
    ): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            validateIdentity(identity)
            listOf(
                location.accountId,
                location.title,
                location.driveId,
                location.remoteVaultId,
                location.sourceRootId,
                location.canonicalServer,
                location.rootWebDavUrl,
                location.vaultPath,
            ).forEach(::requireValidText)
            DataOutputStream(bytes).use { out ->
                listOf("raiun-offline-index-v2", encodeLocation(location), generation, purpose).forEach { field ->
                    val value = utf8(field)
                    out.writeInt(value.size)
                    out.write(value)
                }
                val identityValue = identityBytes(identity)
                out.writeInt(identityValue.size)
                out.write(identityValue)
                out.writeInt(token.size)
                out.write(token)
            }
            bytes.toByteArray()
        }

    fun pathToken(
        key: ByteArray,
        path: String,
    ): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            update("offline-index-path-v2\u0000".toByteArray())
            doFinal(utf8(path))
        }

    fun encrypt(
        key: ByteArray,
        aad: ByteArray,
        plain: ByteArray,
        sequence: Long? = null,
    ): ByteArray {
        val nonce =
            if (sequence == null) {
                ByteArray(12).also(random::nextBytes)
            } else {
                ByteBuffer
                    .allocate(12)
                    .putInt(0x52564f32)
                    .putLong(sequence)
                    .array()
            }
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(aad)
                nonce +
                    doFinal(plain)
            }
        } finally {
            nonce.fill(0)
            aad.fill(0)
        }
    }

    fun decrypt(
        key: ByteArray,
        aad: ByteArray,
        sealed: ByteArray,
        authenticationFailure: OpenCloudError = OpenCloudError.DownloadIntegrity,
    ): ByteArray =
        try {
            if (sealed.size < 28) integrity()
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, sealed, 0, 12))
                updateAAD(aad)
                doFinal(sealed, 12, sealed.size - 12)
            }
        } catch (_: java.security.GeneralSecurityException) {
            throw OpenCloudException(authenticationFailure)
        } finally {
            aad.fill(0)
        }

    fun updateHash(
        hash: MessageDigest,
        sequence: Long,
        token: ByteArray,
        sealed: ByteArray,
    ) {
        val header =
            ByteArrayOutputStream().use { bytes ->
                DataOutputStream(bytes).use {
                    it.writeLong(sequence)
                    it.writeInt(sealed.size)
                    it.write(token)
                }
                bytes.toByteArray()
            }
        hash.update(header)
        hash.update(sealed)
    }

    fun encodeEntry(entry: OfflineEntry): ByteArray {
        validateTextFields(entry)
        val json =
            JSONObject()
                .put("path", entry.encryptedPath)
                .put("name", entry.rawName)
                .put("id", entry.id)
                .put("folder", entry.isFolder)
                .put("size", entry.size)
                .put("etag", entry.etag)
                .put("blob", entry.blobId)
                .put("digest", entry.digest)
        return utf8(json.toString())
    }

    fun decodeEntry(
        bytes: ByteArray,
        location: VaultLocation,
    ): OfflineEntry {
        val value = JSONObject(text(bytes))
        val entry =
            OfflineEntry(
                value.getString("path"),
                value.getString("name"),
                value.getString("id"),
                value.getBoolean("folder"),
                value.getLong("size"),
                if (value.isNull("etag")) null else value.getString("etag"),
                if (value.isNull("blob")) null else value.getString("blob"),
                if (value.isNull("digest")) null else value.getString("digest"),
            )
        validateTextFields(entry)
        validateOfflineEntry(entry, location)
        return entry
    }

    fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)

    fun text(bytes: ByteArray): String =
        try {
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            integrity()
        }

    private fun utf8(value: String): ByteArray =
        try {
            val buffer =
                Charsets.UTF_8
                    .newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value))
            ByteArray(buffer.remaining()).also(buffer::get)
        } catch (_: java.nio.charset.CharacterCodingException) {
            integrity()
        }

    private fun requireValidText(value: String) {
        utf8(value).fill(0)
    }

    private fun validateTextFields(entry: OfflineEntry) {
        listOfNotNull(
            entry.encryptedPath,
            entry.rawName,
            entry.id,
            entry.etag,
            entry.blobId,
            entry.digest,
        ).forEach(::requireValidText)
    }

    private fun validateIdentity(identity: VaultIdentity) {
        listOf(
            identity.accountId,
            identity.canonicalServer,
            identity.driveId,
            identity.remoteVaultId,
        ).forEach(::requireValidText)
    }
}
