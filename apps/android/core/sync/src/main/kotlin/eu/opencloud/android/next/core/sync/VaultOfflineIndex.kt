package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.aad
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.decodeEntry
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.decrypt
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.deriveIndexKey
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.encrypt
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.integrity
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.pathToken
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.updateHash
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** A bounded visitor must complete successfully before its caller exposes any staged results. */
internal interface OfflineManifest : AutoCloseable {
    fun visit(
        checkActive: () -> Unit = {},
        consume: (OfflineEntry) -> Unit,
    )

    fun find(
        path: String,
        checkActive: () -> Unit = {},
    ): OfflineEntry? {
        var found: OfflineEntry? = null
        visit(checkActive) { if (it.encryptedPath == path) found = it }
        return found
    }

    fun retain(): OfflineManifest = this

    override fun close() = Unit
}

internal class LegacyOfflineManifest(
    private val entries: Map<String, OfflineEntry>,
    private val directory: File? = null,
    private val rootDigest: String? = null,
) : OfflineManifest {
    private var closed = false
    private val lease = directory?.let { VaultOfflineIndex.beginLegacyRead(it, requireNotNull(rootDigest)) }

    @Synchronized override fun visit(
        checkActive: () -> Unit,
        consume: (OfflineEntry) -> Unit,
    ) {
        check(!closed)
        entries.values.forEach {
            checkActive()
            consume(it)
        }
    }

    @Synchronized override fun retain(): OfflineManifest {
        check(!closed)
        return LegacyOfflineManifest(entries, directory, rootDigest)
    }

    @Synchronized override fun close() {
        if (!closed) {
            closed = true
            lease?.close()
        }
    }
}

/** Small overlays hold only a selected entry and its ancestors, never an entire existing index. */
internal fun OfflineManifest.withEntryAndAncestors(
    location: VaultLocation,
    entry: OfflineEntry,
): OfflineManifest =
    replacingEntries(offlineAncestors(location, entry.encryptedPath.substringBeforeLast('/', "")) + entry)

internal fun OfflineManifest.withDirectoryAndAncestors(
    location: VaultLocation,
    path: String,
): OfflineManifest = replacingEntries(offlineAncestors(location, path))

private fun offlineAncestors(
    location: VaultLocation,
    path: String,
): List<OfflineEntry> {
    val root = location.vaultPath.trimEnd('/')
    if (path == root) return emptyList()
    val relative = if (root.isEmpty()) path else path.removePrefix("$root/")
    var parent = root
    return relative.split('/').filter(String::isNotEmpty).map { segment ->
        parent = if (parent.isEmpty()) segment else "$parent/$segment"
        OfflineEntry(parent, segment, "", true, 0, null, null, null)
    }
}

private fun OfflineManifest.replacingEntries(replacements: List<OfflineEntry>): OfflineManifest {
    val source = this
    return object : OfflineManifest {
        override fun visit(
            checkActive: () -> Unit,
            consume: (OfflineEntry) -> Unit,
        ) {
            val pending = replacements.associateBy(OfflineEntry::encryptedPath).toMutableMap()
            source.visit(checkActive) { old ->
                val replacement = pending.remove(old.encryptedPath)
                // Synthetic ancestor records must preserve an existing directory's captured identity.
                consume(if (replacement == null || replacement.isFolder) old else replacement)
            }
            pending.values.forEach {
                checkActive()
                consume(it)
            }
        }
    }
}

internal fun OfflineManifest.retaining(predicate: (OfflineEntry) -> Boolean): OfflineManifest {
    val source = this
    return object : OfflineManifest {
        override fun visit(
            checkActive: () -> Unit,
            consume: (OfflineEntry) -> Unit,
        ) = source.visit(checkActive) { if (predicate(it)) consume(it) }
    }
}

/**
 * Immutable private SQLite generations. All record data is AEAD encrypted; SQL contains only
 * sequence numbers, keyed path tokens and bounded ciphertext chunks. The authenticated root
 * seals the exact ordered membership and count. A complete valid old snapshot can still be replayed.
 */
internal object VaultOfflineIndex {
    private val magic = "RVO2".toByteArray(Charsets.US_ASCII)
    private val readers = ConcurrentHashMap<String, Int>()
    private val blobReaders = ConcurrentHashMap<String, Int>()
    private const val MAX_RECORD_BYTES = 16 * 1024 * 1024
    private const val CHUNK_BYTES = 64 * 1024
    private const val MAX_ROOT_BYTES = 128 * 1024
    private const val APPLICATION_ID = 0x52564f32

    fun recognizes(bytes: ByteArray): Boolean = bytes.size >= 4 && bytes.copyOfRange(0, 4).contentEquals(magic)

    /** Opaque hint for keyless conservative garbage collection; never an authentication decision. */
    fun generation(bytes: ByteArray): String? =
        if (!recognizes(bytes) || bytes.size < 40) {
            null
        } else {
            runCatching {
                String(bytes, 4, 36, Charsets.US_ASCII).also { require(UUID.fromString(it).toString() == it) }
            }.getOrNull()
        }

    @Suppress("TooGenericExceptionCaught") // Every failed construction releases its reader registration.
    fun open(
        directory: File,
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        root: ByteArray,
    ): OfflineManifest {
        val generation = generation(root) ?: integrity()
        val key = deriveIndexKey(material, identity, generation, "root")
        try {
            require(root.size in 69..MAX_ROOT_BYTES)
            val descriptor =
                decrypt(
                    key,
                    aad(identity, location, generation, "root"),
                    root.copyOfRange(40, root.size),
                    authenticationFailure = OpenCloudError.EncryptedUnlockFailed,
                )
            val decoded = decodeDescriptor(descriptor)
            val file = generationFile(directory, generation)
            synchronized(readers) { readers[file.path] = readers.getOrDefault(file.path, 0) + 1 }
            try {
                return Snapshot(
                    file,
                    identity,
                    location,
                    generation,
                    deriveIndexKey(material, identity, generation, "records"),
                    decoded.first,
                    decoded.second,
                )
            } catch (failure: Throwable) {
                release(file)
                throw failure
            }
        } finally {
            key.fill(0)
        }
    }

    private fun decodeDescriptor(descriptor: ByteArray): Pair<Long, ByteArray> =
        try {
            DataInputStream(descriptor.inputStream()).use {
                val count = it.readLong()
                val digest = ByteArray(32).also(it::readFully)
                if (count < 0 || it.read() != -1) integrity()
                count to digest
            }
        } finally {
            descriptor.fill(0)
        }

    /** Builds and fsyncs all generation bytes before returning a root that can be atomically published. */
    @Suppress("LongParameterList") // Construction binds the immutable vault identity and live lease.
    fun prepare(
        directory: File,
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        source: OfflineManifest,
        durability: OfflineDurability = OfflineDurability(directory),
        checkActive: () -> Unit = {},
    ): ByteArray {
        durability.requireOwnedDirectory(directory)
        val generation = UUID.randomUUID().toString()
        val file = generationFile(directory, generation)
        check(file.parentFile!!.mkdirs() || file.parentFile!!.isDirectory)
        check(!file.exists())
        val key = deriveIndexKey(material, identity, generation, "records")
        var complete = false
        try {
            lateinit var writer: VaultOfflineIndexWriter
            SQLiteDatabase.openOrCreateDatabase(file, null).use { database ->
                database.rawQuery("PRAGMA journal_mode=DELETE", null).use {
                    check(it.moveToFirst() && it.getString(0).equals("delete", ignoreCase = true))
                }
                database.execSQL("PRAGMA synchronous=FULL")
                database.execSQL("PRAGMA application_id=$APPLICATION_ID")
                database.execSQL("PRAGMA user_version=2")
                database.execSQL(
                    "CREATE TABLE entries (seq INTEGER PRIMARY KEY, " +
                        "pathToken BLOB NOT NULL UNIQUE, size INTEGER NOT NULL)",
                )
                database.execSQL(
                    "CREATE TABLE chunks (seq INTEGER NOT NULL, part INTEGER NOT NULL, " +
                        "payload BLOB NOT NULL, PRIMARY KEY(seq, part))",
                )
                database.beginTransaction()
                writer = VaultOfflineIndexWriter(database, identity, location, generation, key, checkActive)
                try {
                    source.visit(checkActive, writer::append)
                    database.setTransactionSuccessful()
                } finally {
                    database.endTransaction()
                }
            }
            checkActive()
            FileOutputStream(file, true).use { it.fd.sync() }
            durability.syncParents(requireNotNull(file.parentFile))
            val descriptor =
                ByteArrayOutputStream().use { bytes ->
                    DataOutputStream(bytes).use {
                        it.writeLong(writer.count)
                        it.write(writer.digest())
                    }
                    bytes.toByteArray()
                }
            val root =
                try {
                    val rootKey = deriveIndexKey(material, identity, generation, "root")
                    try {
                        magic + generation.toByteArray(Charsets.US_ASCII) +
                            encrypt(rootKey, aad(identity, location, generation, "root"), descriptor)
                    } finally {
                        rootKey.fill(0)
                    }
                } finally {
                    descriptor.fill(0)
                }
            // Independently read what was persisted before allowing a pointer to refer to it.
            open(directory, identity, location, material, root).use { it.visit(checkActive) {} }
            complete = true
            return root
        } finally {
            key.fill(0)
            if (!complete) deleteGeneration(file)
        }
    }

    fun cleanup(
        directory: File,
        retainedRoots: List<ByteArray>,
    ) {
        if (retainedRoots.isEmpty() || retainedRoots.any { !recognizedRoot(it) }) return
        val retained = retainedRoots.mapNotNull(::generation).toSet()
        val indexes = File(directory, "indexes").canonicalFile
        if (!indexes.isDirectory) return
        check(
            !java.nio.file.Files
                .isSymbolicLink(File(directory, "indexes").toPath()),
        )
        synchronized(readers) {
            java.nio.file.Files.newDirectoryStream(indexes.toPath(), "*.db").use { paths ->
                for (path in paths) {
                    val file = path.toFile()
                    if (canDiscardGeneration(file, retained)) deleteGeneration(file)
                }
            }
        }
    }

    private fun canDiscardGeneration(
        file: File,
        retained: Set<String>,
    ): Boolean {
        val id = file.name.removeSuffix(".db")
        val ownedName = runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)
        val unused = id !in retained && readers.getOrDefault(file.path, 0) == 0
        return ownedName && unused && isOwnedGeneration(file)
    }

    private fun recognizedRoot(bytes: ByteArray): Boolean {
        if (generation(bytes) != null) return true
        return bytes.size >= 32 && bytes.copyOfRange(0, 4).contentEquals("RVO1".toByteArray(Charsets.US_ASCII))
    }

    fun beginLegacyRead(
        directory: File,
        rootDigest: String,
    ): AutoCloseable {
        require(rootDigest.matches(Regex("[a-f0-9]{64}")))
        val marker = File(File(directory, "indexes"), "legacy-$rootDigest").canonicalFile
        synchronized(readers) { readers[marker.path] = readers.getOrDefault(marker.path, 0) + 1 }
        return AutoCloseable { release(marker) }
    }

    fun beginBlobRead(
        directory: File,
        blobId: String,
    ): AutoCloseable {
        val path = File(File(directory, "blobs"), blobId).canonicalPath
        synchronized(blobReaders) { blobReaders[path] = blobReaders.getOrDefault(path, 0) + 1 }
        return AutoCloseable {
            synchronized(blobReaders) {
                val left = blobReaders.getOrDefault(path, 0) - 1
                if (left <= 0) blobReaders.remove(path) else blobReaders[path] = left
            }
        }
    }

    fun blobInUse(file: File): Boolean =
        synchronized(blobReaders) { blobReaders.getOrDefault(file.canonicalPath, 0) > 0 }

    fun previousGenerationInUse(
        directory: File,
        currentRoot: ByteArray,
    ): Boolean {
        val current =
            generation(currentRoot)?.let { "$it.db" }
                ?: "legacy-" +
                MessageDigest.getInstance("SHA-256").digest(currentRoot).joinToString("") { "%02x".format(it) }
        val parent = File(directory, "indexes").canonicalPath + File.separator
        return synchronized(readers) {
            readers.any { (path, count) ->
                count > 0 && path.startsWith(parent) && File(path).name != current
            }
        }
    }

    @Suppress("LongParameterList") // A reader owns its identity, generation, key and membership root.
    private class Snapshot(
        private val file: File,
        private val identity: VaultIdentity,
        private val location: VaultLocation,
        private val generation: String,
        private val key: ByteArray,
        private val count: Long,
        private val expectedDigest: ByteArray,
    ) : OfflineManifest {
        private var closed = false

        @Synchronized override fun visit(
            checkActive: () -> Unit,
            consume: (OfflineEntry) -> Unit,
        ) {
            check(!closed)
            val hash = MessageDigest.getInstance("SHA-256")
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
                // API26 refuses beginTransaction on an OPEN_READONLY handle. This connection never mutates rows.
                database.beginTransactionNonExclusive()
                try {
                    val read = scanRecords(database, hash, checkActive, consume)
                    if (read != count || !MessageDigest.isEqual(hash.digest(), expectedDigest)) integrity()
                    requireNoOrphanChunks(database)
                    checkActive()
                    database.setTransactionSuccessful()
                } finally {
                    database.endTransaction()
                }
            }
        }

        private fun scanRecords(
            database: SQLiteDatabase,
            hash: MessageDigest,
            checkActive: () -> Unit,
            consume: (OfflineEntry) -> Unit,
        ): Long {
            var read = 0L
            // Bound SQL projections before CursorWindow or getBlob can materialize untrusted values.
            database
                .rawQuery(
                    "SELECT seq, length(pathToken), substr(pathToken,1,33), size FROM entries ORDER BY seq",
                    null,
                ).use { rows ->
                    while (rows.moveToNext()) {
                        checkActive()
                        val sequence = rows.getLong(0)
                        if (sequence != read || read >= count) integrity()
                        if (rows.getLong(1) != 32L ||
                            rows.getType(0) != android.database.Cursor.FIELD_TYPE_INTEGER
                        ) {
                            integrity()
                        }
                        if (rows.getType(2) != android.database.Cursor.FIELD_TYPE_BLOB ||
                            rows.getType(3) != android.database.Cursor.FIELD_TYPE_INTEGER
                        ) {
                            integrity()
                        }
                        val size = rows.getLong(3)
                        if (size !in 28..MAX_RECORD_BYTES + 28L) integrity()
                        val token = rows.getBlob(2)
                        val sealed = readChunks(database, sequence, size.toInt(), checkActive)
                        try {
                            updateHash(hash, sequence, token, sealed)
                            consume(authenticateRecord(sequence, token, sealed))
                            read = Math.addExact(read, 1)
                        } finally {
                            sealed.fill(0)
                            token.fill(0)
                        }
                    }
                }
            return read
        }

        private fun authenticateRecord(
            sequence: Long,
            token: ByteArray,
            sealed: ByteArray,
        ): OfflineEntry {
            val plain = decrypt(key, aad(identity, location, generation, "record:$sequence", token), sealed)
            val entry =
                try {
                    decodeEntry(plain, location)
                } finally {
                    plain.fill(0)
                }
            val actual = pathToken(key, entry.encryptedPath)
            try {
                if (!MessageDigest.isEqual(actual, token)) integrity()
            } finally {
                actual.fill(0)
            }
            return entry
        }

        @Synchronized override fun retain(): OfflineManifest {
            check(!closed)
            synchronized(readers) { readers[file.path] = readers.getOrDefault(file.path, 0) + 1 }
            return Snapshot(file, identity, location, generation, key.copyOf(), count, expectedDigest.copyOf())
        }

        @Synchronized override fun close() {
            if (!closed) {
                closed = true
                key.fill(0)
                expectedDigest.fill(0)
                release(file)
            }
        }
    }

    private fun readChunks(
        database: SQLiteDatabase,
        sequence: Long,
        size: Int,
        checkActive: () -> Unit,
    ): ByteArray {
        val sealed = ByteArray(size)
        var complete = false
        var offset = 0
        var part = 0L
        try {
            database
                .rawQuery(
                    "SELECT part, length(payload), substr(payload,1,65537) FROM chunks WHERE seq = ? ORDER BY part",
                    arrayOf(sequence.toString()),
                ).use { chunks ->
                    while (chunks.moveToNext()) {
                        checkActive()
                        offset += copyChunk(chunks, sealed, offset, part++)
                    }
                }
            if (offset != sealed.size) integrity()
            complete = true
            return sealed
        } finally {
            if (!complete) sealed.fill(0)
        }
    }

    private fun copyChunk(
        chunks: android.database.Cursor,
        sealed: ByteArray,
        offset: Int,
        part: Long,
    ): Int {
        if (chunks.getType(0) != android.database.Cursor.FIELD_TYPE_INTEGER || chunks.getLong(0) != part) integrity()
        val length = chunks.getLong(1)
        if (length !in 1L..CHUNK_BYTES.toLong() || length > sealed.size - offset) integrity()
        if (chunks.getType(2) != android.database.Cursor.FIELD_TYPE_BLOB) integrity()
        val chunk = chunks.getBlob(2)
        return try {
            chunk.copyInto(sealed, offset)
            chunk.size
        } finally {
            chunk.fill(0)
        }
    }

    private fun requireNoOrphanChunks(database: SQLiteDatabase) {
        database
            .rawQuery(
                "SELECT COUNT(*) FROM chunks WHERE seq IS NULL OR seq NOT IN (SELECT seq FROM entries)",
                null,
            ).use {
                if (!it.moveToFirst() || it.getLong(0) != 0L) integrity()
            }
    }

    private fun generationFile(
        directory: File,
        id: String,
    ): File {
        require(UUID.fromString(id).toString() == id)
        val indexes = File(directory, "indexes")
        val file = File(indexes, "$id.db")
        val sidecars = listOf(File(file.path + "-journal"), File(file.path + "-wal"), File(file.path + "-shm"))
        (listOf(directory, indexes, file) + sidecars).forEach {
            check(
                !java.nio.file.Files
                    .isSymbolicLink(it.toPath()),
            )
        }
        return File(indexes, "$id.db").canonicalFile
    }

    private fun release(file: File) =
        synchronized(readers) {
            val remaining = readers.getOrDefault(file.path, 0) - 1
            if (remaining <= 0) readers.remove(file.path) else readers[file.path] = remaining
            Unit
        }

    private fun isOwnedGeneration(file: File): Boolean =
        try {
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { database ->
                val owner =
                    database.rawQuery("PRAGMA application_id", null).use {
                        it.moveToFirst() &&
                            it.getInt(0) == APPLICATION_ID
                    }
                val version =
                    database
                        .rawQuery(
                            "PRAGMA user_version",
                            null,
                        ).use { it.moveToFirst() && it.getInt(0) == 2 }
                owner && version
            }
        } catch (_: android.database.sqlite.SQLiteException) {
            // Unknown/corrupt files are retained; opaque filenames alone never authorize their deletion.
            false
        }

    private fun deleteGeneration(file: File) {
        listOf(file, File(file.path + "-journal"), File(file.path + "-wal"), File(file.path + "-shm")).forEach {
            check(
                !java.nio.file.Files
                    .isSymbolicLink(it.toPath()),
            )
            if (it.exists() && !it.delete()) throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
        }
    }
}
