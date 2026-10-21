package eu.opencloud.android.next.core.security

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Local offer history only. The vault key itself remains in [VaultKeyStore] and Android Keystore. */
class VaultPreferences(
    context: Context,
) {
    private val directory = File(context.applicationContext.noBackupFilesDir, DIRECTORY)

    fun entries(): List<VaultPreferenceEntry> =
        synchronized(LOCK) {
            recordFiles().map(::readEntry)
        }

    fun status(identity: VaultIdentity): VaultPreferenceStatus? =
        synchronized(LOCK) {
            readEntryFile(fileFor(identity))?.status
        }

    fun remember(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind = VaultPreferenceTargetKind.FOLDER,
    ) = write(identity, title, targetKind, VaultPreferenceStatus.REMEMBERED)

    fun decline(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind = VaultPreferenceTargetKind.FOLDER,
    ) = write(identity, title, targetKind, VaultPreferenceStatus.DECLINED)

    /** Remove only the local offer marker; it does not delete biometric key material. */
    fun remove(identity: VaultIdentity): Unit =
        synchronized(LOCK) {
            deleteAtomic(fileFor(identity))
        }

    /** Clear all remembered and declined markers so password-unlocked vaults can ask again. */
    fun reset(): Unit =
        synchronized(LOCK) {
            recordFiles().forEach(::deleteAtomic)
        }

    /** Delete only markers whose validated identity belongs to this explicitly removed account. */
    fun forgetAccount(accountId: String): Unit =
        synchronized(LOCK) {
            require(accountId.isNotBlank())
            // Validate the entire inventory before deleting anything. Unknown ownership fails closed.
            val targets =
                recordFiles()
                    .map { file -> file to readEntry(file) }
                    .filter { (_, entry) -> entry.identity.accountId == accountId }
            targets.forEach { (file, _) ->
                deleteAtomic(file)
                if (file.exists() || File(file.path + ".bak").exists() || File(file.path + ".new").exists()) {
                    throw VaultPreferencesException()
                }
            }
        }

    private fun recordFiles(): List<File> {
        if (!directory.exists()) return emptyList()
        val files = directory.listFiles() ?: throw VaultPreferencesException()
        files.filter { it.name.endsWith(".$EXTENSION.new") }.forEach { pending ->
            val base = File(directory, pending.name.removeSuffix(".new"))
            if (!base.exists() && !File(base.path + ".bak").exists()) throw VaultPreferencesException()
        }
        return files
            .mapNotNull { file ->
                when {
                    file.name.endsWith(".$EXTENSION") -> file
                    file.name.endsWith(".$EXTENSION.bak") -> File(directory, file.name.removeSuffix(".bak"))
                    else -> null
                }
            }.distinctBy(File::getName)
    }

    @Suppress("TooGenericExceptionCaught") // Roll back the atomic write for every failure, then rethrow.
    private fun write(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
        status: VaultPreferenceStatus,
    ): Unit =
        synchronized(LOCK) {
            require(title.isNotBlank())
            val bytes = encode(identity, title, targetKind, status)
            val file = AtomicFile(fileFor(identity))
            var stream: FileOutputStream? = null
            try {
                check(directory.exists() || directory.mkdirs()) { "Vault preferences are unavailable." }
                stream = file.startWrite()
                stream.write(bytes)
                file.finishWrite(stream)
                stream = null
            } catch (error: Throwable) {
                stream?.let(file::failWrite)
                throw error
            } finally {
                bytes.fill(0)
            }
        }

    private fun readEntry(file: File): VaultPreferenceEntry = readEntryFile(file) ?: throw VaultPreferencesException()

    private fun readEntryFile(file: File): VaultPreferenceEntry? {
        val atomicFile = AtomicFile(file)
        if (!file.exists() && !File(file.path + ".bak").exists()) return null
        val bytes =
            try {
                atomicFile.openRead().use { input ->
                    if (input.available() !in 1..MAX_RECORD_BYTES) throw VaultPreferencesException()
                    input.readBytes()
                }
            } catch (error: java.io.IOException) {
                throw VaultPreferencesException(error)
            }
        return try {
            decode(bytes).also { entry ->
                require(file.name == filename(entry.identity)) { "Vault preference identity mismatch." }
            }
        } finally {
            bytes.fill(0)
        }
    }

    private fun encode(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
        status: VaultPreferenceStatus,
    ): ByteArray {
        val identityBytes = identity.encoded
        val titleBytes = encodeText(title, MAX_TITLE_BYTES)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(MAGIC)
                output.writeInt(VERSION)
                output.writeInt(identityBytes.size)
                output.write(identityBytes)
                output.writeInt(titleBytes.size)
                output.write(titleBytes)
                output.writeByte(targetKind.ordinal)
                output.writeByte(status.ordinal)
            }
            identityBytes.fill(0)
            titleBytes.fill(0)
            bytes.toByteArray()
        }
    }

    @Suppress("TooGenericExceptionCaught") // Normalize malformed local records while preserving the cause.
    private fun decode(bytes: ByteArray): VaultPreferenceEntry =
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                require(input.readInt() == MAGIC && input.readInt() == VERSION)
                val identitySize = input.readInt()
                require(identitySize in 1..MAX_IDENTITY_BYTES)
                val identityBytes = ByteArray(identitySize).also(input::readFully)
                val identity = decodeIdentity(identityBytes)
                identityBytes.fill(0)
                val titleSize = input.readInt()
                require(titleSize in 1..MAX_TITLE_BYTES)
                val titleBytes = ByteArray(titleSize).also(input::readFully)
                val title = decodeText(titleBytes)
                titleBytes.fill(0)
                val targetKind = VaultPreferenceTargetKind.entries[input.readUnsignedByte()]
                val status = VaultPreferenceStatus.entries[input.readUnsignedByte()]
                require(input.available() == 0)
                VaultPreferenceEntry(identity, title, targetKind, status)
            }
        } catch (error: Exception) {
            throw VaultPreferencesException(error)
        }

    private fun decodeIdentity(bytes: ByteArray): VaultIdentity =
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == IDENTITY_VERSION)
            val fields =
                List(IDENTITY_FIELD_COUNT) {
                    val size = input.readInt()
                    require(size in 1..MAX_IDENTITY_FIELD_BYTES)
                    val field = ByteArray(size).also(input::readFully)
                    decodeText(field).also { field.fill(0) }
                }
            require(input.available() == 0)
            VaultIdentity(fields[0], fields[1], fields[2], fields[3]).also {
                require(MessageDigest.isEqual(it.encoded, bytes))
            }
        }

    private fun encodeText(
        value: String,
        maxBytes: Int,
    ): ByteArray =
        StandardCharsets.UTF_8
            .newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
            .let { buffer ->
                require(buffer.remaining() in 1..maxBytes)
                ByteArray(buffer.remaining()).also(buffer::get)
            }

    private fun decodeText(bytes: ByteArray): String =
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()

    private fun fileFor(identity: VaultIdentity) = File(directory, filename(identity))

    private fun filename(identity: VaultIdentity): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(identity.encoded)
            .joinToString("") { "%02x".format(it) } + ".$EXTENSION"

    private fun deleteAtomic(file: File) {
        AtomicFile(file).delete()
    }

    companion object {
        private const val DIRECTORY = "vault-preferences"
        private const val EXTENSION = "preference"
        private const val MAGIC = 0x52565031
        private const val VERSION = 1
        private const val IDENTITY_VERSION = 1
        private const val IDENTITY_FIELD_COUNT = 4
        private const val MAX_IDENTITY_FIELD_BYTES = 4096
        private const val MAX_IDENTITY_BYTES = 16 * 1024
        private const val MAX_TITLE_BYTES = 2048
        private const val MAX_RECORD_BYTES = MAX_IDENTITY_BYTES + MAX_TITLE_BYTES + 64
        private val LOCK = Any()
    }
}

data class VaultPreferenceEntry(
    val identity: VaultIdentity,
    val title: String,
    val targetKind: VaultPreferenceTargetKind,
    val status: VaultPreferenceStatus,
)

enum class VaultPreferenceTargetKind { FOLDER, SPACE }

enum class VaultPreferenceStatus { REMEMBERED, DECLINED }

class VaultPreferencesException(
    cause: Throwable? = null,
) : IllegalStateException("Vault biometric preferences are invalid or unavailable.", cause)
