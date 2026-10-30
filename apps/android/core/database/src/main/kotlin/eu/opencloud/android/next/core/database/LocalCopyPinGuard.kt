package eu.opencloud.android.next.core.database

import android.database.Cursor
import androidx.sqlite.db.SimpleSQLiteQuery
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Bounded current selection authority, including ancestors hidden by an outer pinned root. */
internal class LocalCopyPinGuard(
    private val database: FileBrowserDatabase,
) {
    fun digest(
        resource: ResourceEntity,
        checkActive: () -> Unit,
    ): ByteArray {
        val hash = MessageDigest.getInstance("SHA-256")
        hash.text("raiun-local-copy-selection-v1")
        resourcePins(resource, hash, checkActive)
        pendingPins(resource, hash, checkActive)
        operationPins(resource, hash, checkActive)
        return hash.digest()
    }

    private fun resourcePins(
        resource: ResourceEntity,
        hash: MessageDigest,
        checkActive: () -> Unit,
    ) {
        hash.text("resources")
        var after: String? = null
        while (true) {
            checkActive()
            var count = 0
            database.openHelper.writableDatabase
                .query(
                    SimpleSQLiteQuery(
                        "SELECT r.* FROM resources r WHERE r.accountId=? AND r.spaceId=? AND r.offlinePinned=1 " +
                            "AND (r.remoteId=? OR (r.kind='FOLDER' AND ${covers("r.path")})) " +
                            "AND (? IS NULL OR r.remoteId COLLATE BINARY > ?) " +
                            "ORDER BY r.remoteId COLLATE BINARY LIMIT 128",
                        arrayOf(
                            resource.accountId,
                            resource.spaceId,
                            resource.remoteId,
                            resource.path,
                            resource.path,
                            after,
                            after,
                        ),
                    ),
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        checkActive()
                        hash.row(cursor)
                        after = cursor.getString(cursor.getColumnIndexOrThrow("remoteId"))
                        count++
                    }
                }
            if (count == 0) break
        }
        hash.text("end-resources")
    }

    private fun pendingPins(
        resource: ResourceEntity,
        hash: MessageDigest,
        checkActive: () -> Unit,
    ) {
        hash.text("pending")
        var after: String? = null
        while (true) {
            checkActive()
            var count = 0
            database.openHelper.writableDatabase
                .query(
                    SimpleSQLiteQuery(
                        "SELECT p.* FROM pending_pins p WHERE p.accountId=? AND p.spaceId=? AND ${covers("p.path")} " +
                            "AND (? IS NULL OR p.path COLLATE BINARY > ?) ORDER BY p.path COLLATE BINARY LIMIT 128",
                        arrayOf(resource.accountId, resource.spaceId, resource.path, resource.path, after, after),
                    ),
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        checkActive()
                        hash.row(cursor)
                        after = cursor.getString(cursor.getColumnIndexOrThrow("path"))
                        count++
                    }
                }
            if (count == 0) break
        }
        hash.text("end-pending")
    }

    private fun operationPins(
        resource: ResourceEntity,
        hash: MessageDigest,
        checkActive: () -> Unit,
    ) {
        hash.text("operations")
        var afterOperation: String? = null
        var afterPath: String? = null
        while (true) {
            checkActive()
            var count = 0
            database.openHelper.writableDatabase
                .query(
                    SimpleSQLiteQuery(
                        "SELECT p.operationId,p.relativePath,o.sourceSpaceId,o.sourcePath FROM operation_pins p " +
                            "JOIN file_operations o ON o.id=p.operationId WHERE o.accountId=? AND o.sourceSpaceId=? " +
                            "AND ${covers("o.sourcePath || p.relativePath")} " +
                            "AND (? IS NULL OR p.operationId COLLATE BINARY > ? OR " +
                            "(p.operationId=? AND p.relativePath COLLATE BINARY > ?)) " +
                            "ORDER BY p.operationId COLLATE BINARY,p.relativePath COLLATE BINARY LIMIT 128",
                        arrayOf(
                            resource.accountId,
                            resource.spaceId,
                            resource.path,
                            resource.path,
                            afterOperation,
                            afterOperation,
                            afterOperation,
                            afterPath,
                        ),
                    ),
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        checkActive()
                        hash.row(cursor)
                        afterOperation = cursor.getString(0)
                        afterPath = cursor.getString(1)
                        count++
                    }
                }
            if (count == 0) break
        }
        hash.text("end-operations")
    }

    companion object {
        fun emptyDigest(): ByteArray =
            MessageDigest.getInstance("SHA-256").run {
                listOf(
                    "raiun-local-copy-selection-v1",
                    "resources",
                    "end-resources",
                    "pending",
                    "end-pending",
                    "operations",
                    "end-operations",
                ).forEach { text(it) }
                digest()
            }

        /** One parameter, the selected descendant path; '=' also covers an exact file selection. */
        fun covers(column: String): String =
            "(? = $column OR substr(?,1,length(rtrim($column,'/'))+1)=rtrim($column,'/') || '/')"
    }
}

private fun MessageDigest.row(cursor: Cursor) {
    update(1)
    integer(cursor.columnCount.toLong())
    for (column in 0 until cursor.columnCount) {
        val type = cursor.getType(column)
        update(type.toByte())
        when (type) {
            Cursor.FIELD_TYPE_NULL -> Unit
            Cursor.FIELD_TYPE_INTEGER -> integer(cursor.getLong(column))
            Cursor.FIELD_TYPE_STRING -> text(cursor.getString(column))
            else -> error("Unexpected local-copy selection field")
        }
    }
}

private fun MessageDigest.integer(value: Long) = update(ByteBuffer.allocate(8).putLong(value).array())

private fun MessageDigest.text(value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    integer(bytes.size.toLong())
    update(bytes)
}
