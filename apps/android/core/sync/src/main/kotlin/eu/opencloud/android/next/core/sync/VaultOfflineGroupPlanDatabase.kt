package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import java.io.File
import java.security.MessageDigest

internal data class VaultOfflineGroupPlanSummary(
    val members: Long,
    val files: Long,
    val bytes: Long,
    val digest: ByteArray,
) {
    fun matchesCounts(
        expectedMembers: Long,
        expectedFiles: Long,
        expectedBytes: Long,
    ): Boolean = members == expectedMembers && files == expectedFiles && bytes == expectedBytes
}

internal data class VaultOfflineGroupPlanRecord(
    val member: VaultOfflineGroupMember,
    val payload: ByteArray,
)

/** All on-disk strings are original opaque paths/IDs. Validation uses disk uniqueness, never a whole-tree set. */
internal class VaultOfflineGroupPlanDatabase(
    private val file: File,
) {
    @Suppress("TooGenericExceptionCaught") // Every failed database construction must release its native connection.
    fun create(): SQLiteDatabase {
        val database = SQLiteDatabase.openOrCreateDatabase(file, null)
        try {
            database.rawQuery("PRAGMA journal_mode=DELETE", null).use {
                require(
                    it.moveToFirst() && it.getString(0) == "delete",
                )
            }
            database.execSQL("PRAGMA synchronous=FULL")
            database.execSQL("CREATE TABLE entries (seq INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
            createTree(database)
            return database
        } catch (failure: Throwable) {
            database.close()
            throw failure
        }
    }

    /** Validation is read-only so a rejected descriptor leaves the preparation reusable. */
    fun validateAppend(
        database: SQLiteDatabase,
        member: VaultOfflineGroupMember,
        pending: List<VaultOfflineGroupPlanRecord>,
    ) {
        if (member.sequence > 0) {
            val parent = member.source.relativePath.substringBeforeLast('/', "")
            val pendingParent = pending.any { it.member.source.relativePath == parent && it.member.source.isFolder }
            val committedParent =
                database.rawQuery("SELECT folder FROM tree WHERE path = ?", arrayOf(parent)).use {
                    it.moveToFirst() && it.getInt(0) == 1
                }
            if (!pendingParent && !committedParent) VaultOfflineGroupPlanCodec.integrity()
        }
        val pendingDuplicate =
            pending.any {
                it.member.source.relativePath == member.source.relativePath || it.member.source.id == member.source.id
            }
        val committedDuplicate =
            database
                .rawQuery(
                    "SELECT 1 FROM tree WHERE path = ? OR sourceId = ? LIMIT 1",
                    arrayOf(member.source.relativePath, member.source.id),
                ).use { it.moveToFirst() }
        if (pendingDuplicate || committedDuplicate) VaultOfflineGroupPlanCodec.integrity()
    }

    /** No transaction or cursor escapes this synchronous batch, even when a caller later changes threads. */
    fun appendBatch(
        database: SQLiteDatabase,
        pending: List<VaultOfflineGroupPlanRecord>,
        checkActive: () -> Unit,
    ) {
        require(pending.size in 1..128)
        require(pending.sumOf { it.payload.size.toLong() } <= VaultOfflineGroupPlanCodec.MAX_RECORD_BYTES)
        database.beginTransaction()
        try {
            pending.forEach { record ->
                checkActive()
                requireLength(record.payload.size.toLong())
                checkTree(database, record.member)
                database.insertOrThrow(
                    "entries",
                    null,
                    ContentValues().apply {
                        put("seq", record.member.sequence)
                        put("payload", record.payload)
                    },
                )
            }
            checkActive()
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    fun closeWriter(database: SQLiteDatabase) = database.close()

    fun page(
        context: VaultOfflineGroupContext,
        after: Long?,
        limit: Int,
    ): List<VaultOfflineGroupMember> {
        require(limit in 1..128 && (after == null || after >= 0))
        return read { database ->
            database
                .rawQuery(
                    "$ROWS " +
                        "WHERE seq > ? ORDER BY seq LIMIT ?",
                    arrayOf((after ?: -1L).toString(), limit.toString()),
                ).use { cursor ->
                    buildList {
                        var size = 0L
                        while (cursor.moveToNext()) {
                            val length = cursor.getLong(1)
                            requireLength(length)
                            if (isNotEmpty() && size + length > 512 * 1024) break
                            if (cursor.isNull(0) || cursor.isNull(2)) VaultOfflineGroupPlanCodec.integrity()
                            val bytes = cursor.getBlob(2)
                            if (bytes.size.toLong() != length) VaultOfflineGroupPlanCodec.integrity()
                            val member = VaultOfflineGroupPlanCodec.readMember(context, bytes)
                            if (member.sequence != cursor.getLong(0)) VaultOfflineGroupPlanCodec.integrity()
                            add(member)
                            size += length
                        }
                    }
                }
        }
    }

    fun scan(
        context: VaultOfflineGroupContext,
        checkActive: () -> Unit,
        consume: (VaultOfflineGroupMember) -> Unit,
    ): VaultOfflineGroupPlanSummary =
        withTree { tree ->
            read { database -> summary(database, tree, context, checkActive, consume) }
        }

    /** Full first-pass authentication precedes every callback; the second pass uses the same read transaction. */
    fun verifiedVisit(
        context: VaultOfflineGroupContext,
        checkActive: () -> Unit,
        validate: (VaultOfflineGroupMember) -> Unit,
        accept: (VaultOfflineGroupPlanSummary) -> Unit,
        consume: (VaultOfflineGroupMember) -> Unit,
    ) = withTree { tree ->
        read { database ->
            val summary = summary(database, tree, context, checkActive, validate)
            accept(summary)
            val emitted = each(database, context, checkActive) { member, _ -> consume(member) }
            if (emitted != summary.members) VaultOfflineGroupPlanCodec.integrity()
            checkActive()
        }
    }

    private fun summary(
        database: SQLiteDatabase,
        tree: SQLiteDatabase,
        context: VaultOfflineGroupContext,
        checkActive: () -> Unit,
        consume: (VaultOfflineGroupMember) -> Unit,
    ): VaultOfflineGroupPlanSummary {
        val digest = MessageDigest.getInstance("SHA-256")
        var files = 0L
        var total = 0L
        val count =
            each(database, context, checkActive) { member, bytes ->
                checkTree(tree, member)
                VaultOfflineGroupPlanCodec.update(digest, member.sequence, bytes)
                if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                    files = Math.addExact(files, 1L)
                    total = Math.addExact(total, member.source.size)
                }
                consume(member)
            }
        if (count == 0L) VaultOfflineGroupPlanCodec.integrity()
        return VaultOfflineGroupPlanSummary(count, files, total, digest.digest())
    }

    private fun each(
        database: SQLiteDatabase,
        context: VaultOfflineGroupContext,
        checkActive: () -> Unit,
        consume: (VaultOfflineGroupMember, ByteArray) -> Unit,
    ): Long {
        var count = 0L
        database.rawQuery("$ROWS ORDER BY seq", null).use { cursor ->
            while (cursor.moveToNext()) {
                checkActive()
                if (cursor.isNull(0) || cursor.getLong(0) != count) VaultOfflineGroupPlanCodec.integrity()
                val length = cursor.getLong(1)
                requireLength(length)
                if (cursor.isNull(2)) VaultOfflineGroupPlanCodec.integrity()
                val bytes = cursor.getBlob(2)
                if (bytes.size.toLong() != length) VaultOfflineGroupPlanCodec.integrity()
                val member = VaultOfflineGroupPlanCodec.readMember(context, bytes)
                if (member.sequence != count) VaultOfflineGroupPlanCodec.integrity()
                consume(member, bytes)
                count = Math.addExact(count, 1L)
            }
        }
        checkActive()
        return count
    }

    private fun <T> withTree(action: (SQLiteDatabase) -> T): T {
        val temporary = File.createTempFile("validate-", ".db", file.parentFile)
        try {
            return SQLiteDatabase.openOrCreateDatabase(temporary, null).use { tree ->
                createTree(tree)
                tree.beginTransaction()
                try {
                    action(tree)
                } finally {
                    tree.endTransaction()
                }
            }
        } finally {
            deleteDatabase(temporary)
        }
    }

    private fun <T> read(action: (SQLiteDatabase) -> T): T =
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
            // API26 refuses transactions on OPEN_READONLY handles. This scope never mutates plan rows.
            database.beginTransactionNonExclusive()
            try {
                action(database).also { database.setTransactionSuccessful() }
            } finally {
                database.endTransaction()
            }
        }

    private fun createTree(database: SQLiteDatabase) {
        database.execSQL(
            "CREATE TABLE tree (path TEXT PRIMARY KEY, sourceId TEXT NOT NULL UNIQUE, folder INTEGER NOT NULL)",
        )
    }

    private fun checkTree(
        database: SQLiteDatabase,
        member: VaultOfflineGroupMember,
    ) {
        validateAppend(database, member, emptyList())
        database.insertOrThrow(
            "tree",
            null,
            ContentValues().apply {
                put("path", member.source.relativePath)
                put("sourceId", member.source.id)
                put("folder", if (member.source.isFolder) 1 else 0)
            },
        )
    }

    private fun requireLength(length: Long) {
        if (length !in 1..VaultOfflineGroupPlanCodec.MAX_RECORD_BYTES.toLong()) VaultOfflineGroupPlanCodec.integrity()
    }

    companion object {
        private const val ROWS =
            "SELECT CASE WHEN typeof(seq)='integer' THEN seq ELSE NULL END, length(payload), " +
                "CASE WHEN typeof(payload)='blob' AND length(payload) BETWEEN 1 AND 1048576 " +
                "THEN substr(payload,1,1048577) ELSE NULL END FROM entries"

        fun deleteDatabase(file: File) {
            listOf(file, File(file.path + "-journal"), File(file.path + "-wal"), File(file.path + "-shm")).forEach {
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(it.toPath()),
                )
                if (it.exists()) check(it.delete())
            }
        }
    }
}
