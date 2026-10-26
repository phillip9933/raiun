package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteDiskIOException
import android.database.sqlite.SQLiteFullException
import eu.opencloud.android.next.core.database.FolderSnapshotReader
import eu.opencloud.android.next.core.database.FolderSnapshotRow
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteFolderEntry
import eu.opencloud.android.next.core.network.RemoteResource
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Disposable indexed listing. Plain names stay inside authenticated per-record ciphertext. */
internal class StagedRemoteFolder private constructor(
    private val file: File,
    private val encryptionKey: ByteArray,
    private val indexKey: ByteArray,
) : Closeable {
    private val random = SecureRandom()
    private val database = SQLiteDatabase.openOrCreateDatabase(file, null)
    private var pending = 0
    private var finished = false
    private var closed = false

    init {
        initializeDatabase()
    }

    // Initialization and teardown must run for Errors as well as Exceptions, so suppression is local.
    @Suppress("TooGenericExceptionCaught")
    private fun initializeDatabase() {
        try {
            database.execSQL("CREATE TABLE paths (digest TEXT PRIMARY KEY)")
            database.execSQL("CREATE TABLE collection_ids (digest TEXT PRIMARY KEY)")
            database.execSQL(
                "CREATE TABLE entries (seq INTEGER PRIMARY KEY AUTOINCREMENT, pathDigest TEXT NOT NULL UNIQUE, " +
                    "idDigest TEXT NOT NULL UNIQUE, visible INTEGER NOT NULL, payload BLOB NOT NULL)",
            )
            database.beginTransaction()
        } catch (failure: Throwable) {
            database.close()
            throw failure
        }
    }

    fun registerCanonicalPath(path: String): Boolean {
        val values = ContentValues().apply { put("digest", digest("url", path).toHex()) }
        return storageOperation {
            database.insertWithOnConflict("paths", null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L
        }
    }

    fun registerCollectionId(id: String): Boolean {
        val hash = digest("id", id).toHex()
        return storageOperation {
            database.rawQuery("SELECT 1 FROM entries WHERE idDigest = ?", arrayOf(hash)).use {
                if (it.moveToFirst()) return@storageOperation false
            }
            database.insertWithOnConflict(
                "collection_ids",
                null,
                ContentValues().apply { put("digest", hash) },
                SQLiteDatabase.CONFLICT_IGNORE,
            ) != -1L
        }
    }

    fun add(entry: RemoteFolderEntry) {
        val resource = entry.resource
        require(resource == null || (resource.id == entry.id && resource.path == entry.path))
        requireNotCollectionId(entry.id)
        val plain = encode(entry)
        val values =
            try {
                ContentValues().apply {
                    if (plain.size > MAX_ENTRY_BYTES) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
                    put("pathDigest", digest("path", entry.path).toHex())
                    put("idDigest", digest("id", entry.id).toHex())
                    put("visible", if (entry.resource == null) 0 else 1)
                    put("payload", encrypt(plain))
                }
            } finally {
                plain.fill(0)
            }
        insertEntry(values)
        if (++pending == BATCH_SIZE) {
            storageOperation {
                database.setTransactionSuccessful()
                database.endTransaction()
                database.beginTransaction()
            }
            pending = 0
        }
    }

    fun finish() {
        storageOperation {
            database.setTransactionSuccessful()
            database.endTransaction()
        }
        finished = true
    }

    fun reader(
        accountId: String,
        spaceId: String,
        parentId: String?,
        now: Long,
    ): FolderSnapshotReader =
        object : FolderSnapshotReader {
            override fun containsRemoteId(remoteId: String): Boolean = containsId(remoteId)

            override fun page(afterSequence: Long): List<FolderSnapshotRow> =
                this@StagedRemoteFolder.page(afterSequence).map { staged ->
                    val entry = staged.entry
                    val remote = entry.resource
                    FolderSnapshotRow(
                        staged.sequence,
                        resource =
                            remote?.let {
                                ResourceEntity(
                                    accountId,
                                    spaceId,
                                    it.id,
                                    parentId,
                                    it.path,
                                    it.name,
                                    if (it.folder) ResourceKind.FOLDER else ResourceKind.FILE,
                                    it.mimeType,
                                    it.size,
                                    it.eTag,
                                    it.modifiedAtEpochMillis,
                                    it.createdAtEpochMillis.takeIf { value -> value > 0 } ?: now,
                                    isFavorite = it.favorite,
                                )
                            },
                        excludedVaultPath = if (remote == null) entry.path else null,
                    )
                }
        }

    fun containsId(id: String): Boolean {
        check(finished)
        return storageOperation {
            database
                .rawQuery(
                    "SELECT 1 FROM entries WHERE idDigest = ? AND visible = 1",
                    arrayOf(digest("id", id).toHex()),
                ).use {
                    it.moveToFirst()
                }
        }
    }

    fun findEntry(id: String): RemoteFolderEntry? {
        check(finished)
        return storageOperation {
            database.rawQuery("SELECT payload FROM entries WHERE idDigest = ?", arrayOf(digest("id", id).toHex())).use {
                if (!it.moveToFirst()) return@storageOperation null
                val payload = it.getBlob(0)
                require(payload.size <= MAX_ENTRY_BYTES + GCM_OVERHEAD_BYTES)
                val plain =
                    try {
                        decrypt(payload)
                    } finally {
                        payload.fill(0)
                    }
                try {
                    decode(plain).also { entry -> require(entry.id == id) }
                } finally {
                    plain.fill(0)
                }
            }
        }
    }

    fun page(after: Long): List<StagedEntry> {
        check(finished)
        val result = ArrayList<StagedEntry>(BATCH_SIZE)
        var pageBytes = 0
        storageOperation {
            database
                .rawQuery(
                    "SELECT seq, pathDigest, idDigest, visible, payload FROM entries " +
                        "WHERE seq > ? ORDER BY seq LIMIT $BATCH_SIZE",
                    arrayOf(after.toString()),
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        val payload = cursor.getBlob(4)
                        require(payload.size <= MAX_ENTRY_BYTES + GCM_OVERHEAD_BYTES)
                        if (result.isNotEmpty() && pageBytes + payload.size > MAX_PAGE_BYTES) {
                            payload.fill(0)
                            break
                        }
                        val plain =
                            try {
                                decrypt(payload)
                            } finally {
                                payload.fill(0)
                            }
                        val entry =
                            try {
                                decode(plain)
                            } finally {
                                plain.fill(0)
                            }
                        require(cursor.getString(1) == digest("path", entry.path).toHex())
                        require(cursor.getString(2) == digest("id", entry.id).toHex())
                        require(cursor.getInt(3) == if (entry.resource == null) 0 else 1)
                        val resource = entry.resource
                        require(resource == null || (resource.id == entry.id && resource.path == entry.path))
                        pageBytes += payload.size
                        result += StagedEntry(cursor.getLong(0), entry)
                    }
                }
        }
        return result
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            try {
                if (database.inTransaction()) database.endTransaction()
            } finally {
                database.close()
            }
        } finally {
            encryptionKey.fill(0)
            indexKey.fill(0)
            synchronized(activePaths) { activePaths.remove(file.absolutePath) }
            deleteStageFiles(file)
        }
    }

    private fun digest(
        kind: String,
        value: String,
    ): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(indexKey, "HmacSHA256"))
            doFinal("$kind\u0000$value".toByteArray(Charsets.UTF_8))
        }

    private inline fun <T> storageOperation(block: () -> T): T =
        try {
            block()
        } catch (failure: SQLiteFullException) {
            throw OpenCloudException(OpenCloudError.LocalStorage).apply { initCause(failure) }
        } catch (failure: SQLiteDiskIOException) {
            throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed).apply { initCause(failure) }
        }

    private fun requireNotCollectionId(id: String) {
        storageOperation {
            database
                .rawQuery(
                    "SELECT 1 FROM collection_ids WHERE digest = ?",
                    arrayOf(digest("id", id).toHex()),
                ).use {
                    if (it.moveToFirst()) throw OpenCloudException(OpenCloudError.InvalidResponse)
                }
        }
    }

    private fun insertEntry(values: ContentValues) {
        val inserted =
            storageOperation {
                database.insertWithOnConflict("entries", null, values, SQLiteDatabase.CONFLICT_IGNORE)
            }
        if (inserted == -1L) throw OpenCloudException(OpenCloudError.InvalidResponse)
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), GCMParameterSpec(128, nonce))
        return nonce + cipher.doFinal(plain)
    }

    private fun decrypt(encoded: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(encryptionKey, "AES"),
            GCMParameterSpec(128, encoded.copyOfRange(0, 12)),
        )
        return cipher.doFinal(encoded, 12, encoded.size - 12)
    }

    private fun encode(entry: RemoteFolderEntry): ByteArray {
        val bytes = WipingByteArrayOutputStream()
        return try {
            DataOutputStream(bytes).use { output ->
                output.writeString(entry.id)
                output.writeString(entry.path)
                val resource = entry.resource
                output.writeBoolean(resource != null)
                if (resource != null) {
                    output.writeString(resource.name)
                    output.writeBoolean(resource.folder)
                    output.writeNullable(resource.mimeType)
                    output.writeLong(resource.size)
                    output.writeNullable(resource.eTag)
                    output.writeLong(resource.modifiedAtEpochMillis)
                    output.writeLong(resource.createdAtEpochMillis)
                    output.writeBoolean(resource.favorite)
                }
            }
            bytes.toByteArray()
        } finally {
            bytes.wipe()
        }
    }

    private fun decode(bytes: ByteArray): RemoteFolderEntry =
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val id = input.readString()
            val path = input.readString()
            val resource =
                if (input.readBoolean()) {
                    RemoteResource(
                        id,
                        path,
                        input.readString(),
                        input.readBoolean(),
                        input.readNullable(),
                        input.readLong(),
                        input.readNullable(),
                        input.readLong(),
                        input.readLong(),
                        input.readBoolean(),
                    )
                } else {
                    null
                }
            RemoteFolderEntry(id, path, resource)
        }

    private fun DataOutputStream.writeNullable(value: String?) {
        writeBoolean(value != null)
        if (value != null) writeString(value)
    }

    private fun DataInputStream.readNullable(): String? = if (readBoolean()) readString() else null

    private fun DataOutputStream.writeString(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        try {
            if (bytes.size > MAX_FIELD_BYTES) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
            writeInt(bytes.size)
            write(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun DataInputStream.readString(): String {
        val size = readInt()
        require(size in 0..MAX_FIELD_BYTES)
        val bytes = ByteArray(size).also { readFully(it) }
        return try {
            bytes.toString(Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    private fun ByteArray.toHex(): String {
        val chars = CharArray(size * 2)
        forEachIndexed { index, byte ->
            val value = byte.toInt() and 0xff
            chars[index * 2] = HEX_DIGITS[value ushr 4]
            chars[index * 2 + 1] = HEX_DIGITS[value and 0x0f]
        }
        return String(chars)
    }

    private class WipingByteArrayOutputStream : ByteArrayOutputStream() {
        fun wipe() = buf.fill(0)
    }

    internal data class StagedEntry(
        val sequence: Long,
        val entry: RemoteFolderEntry,
    )

    companion object {
        private const val BATCH_SIZE = 128
        private const val MAX_FIELD_BYTES = 512 * 1024
        private const val MAX_ENTRY_BYTES = 768 * 1024
        private const val MAX_PAGE_BYTES = 1024 * 1024
        private const val GCM_OVERHEAD_BYTES = 28
        private const val HEX_DIGITS = "0123456789abcdef"
        private val activePaths = mutableSetOf<String>()

        // A failed constructor can throw Error too; still wipe keys and remove the on-disk stage.
        @Suppress("TooGenericExceptionCaught")
        fun create(cacheDir: File): StagedRemoteFolder {
            val directory = File(cacheDir, "discovery-stage").apply { mkdirs() }
            // Active refreshes may coexist; only remove abandoned files from earlier runs.
            val staleBefore = System.currentTimeMillis() - 24L * 60 * 60 * 1000
            directory
                .listFiles()
                ?.filter {
                    val rootPath =
                        it.absolutePath
                            .removeSuffix("-journal")
                            .removeSuffix("-wal")
                            .removeSuffix("-shm")
                    it.lastModified() < staleBefore && synchronized(activePaths) { rootPath !in activePaths }
                }?.forEach(File::delete)
            val file =
                try {
                    File.createTempFile("folder-", ".sqlite", directory)
                } catch (failure: java.io.IOException) {
                    throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed).apply { initCause(failure) }
                }
            val random = SecureRandom()
            val encryptionKey = ByteArray(32).also(random::nextBytes)
            val indexKey = ByteArray(32).also(random::nextBytes)
            synchronized(activePaths) { activePaths.add(file.absolutePath) }
            return try {
                StagedRemoteFolder(file, encryptionKey, indexKey)
            } catch (failure: Throwable) {
                cleanupFailedStage(file, encryptionKey, indexKey)
                throw failure.toStageFailure()
            }
        }

        private fun Throwable.toStageFailure(): Throwable =
            when (this) {
                is SQLiteFullException ->
                    OpenCloudException(OpenCloudError.LocalStorage).apply {
                        initCause(this@toStageFailure)
                    }
                is SQLiteDiskIOException ->
                    OpenCloudException(OpenCloudError.LocalStorageWriteFailed).apply {
                        initCause(this@toStageFailure)
                    }
                else -> this
            }

        private fun cleanupFailedStage(
            file: File,
            encryptionKey: ByteArray,
            indexKey: ByteArray,
        ) {
            encryptionKey.fill(0)
            indexKey.fill(0)
            synchronized(activePaths) { activePaths.remove(file.absolutePath) }
            deleteStageFiles(file)
        }

        private fun deleteStageFiles(file: File) {
            file.delete()
            File("${file.path}-journal").delete()
            File("${file.path}-wal").delete()
            File("${file.path}-shm").delete()
        }
    }
}
