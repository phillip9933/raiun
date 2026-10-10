package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.BackupReceipt
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import java.io.InputStream
import java.security.MessageDigest

/** Enqueue receipts prevent duplicate jobs across scans/history cleanup; they do not assert server success.
 * Failed/conflicted jobs remain in Uploads for explicit retry/resolution. Timestamps are not a discovery cursor.
 */
internal class BackupInventory(
    context: Context,
    private val pairId: String,
    private val receipts: eu.opencloud.android.next.core.database.BackupReceiptDao =
        FileBrowserDatabase.create(context).backupReceiptDao(),
) {
    suspend fun needsUpload(
        source: String,
        signature: String,
    ): Boolean = receipts.find(pairId, sourceKey(source))?.acceptedSignature != signature

    suspend fun queued(
        source: String,
        signature: String,
    ) {
        val key = sourceKey(source)
        val previous = receipts.find(pairId, key) ?: BackupReceipt(pairId, key)
        receipts.save(previous.copy(acceptedSignature = signature))
    }

    suspend fun stable(
        source: String,
        signature: String,
        modified: Long,
        now: Long,
    ): Boolean =
        if (modified > 0) {
            modified <= now - STABILITY_MILLIS
        } else {
            val key = sourceKey(source)
            val previous = receipts.find(pairId, key) ?: BackupReceipt(pairId, key)
            if (previous.observedSignature == signature) {
                now - previous.observedAt >= STABILITY_MILLIS
            } else {
                receipts.save(previous.copy(observedSignature = signature, observedAt = now))
                false
            }
        }

    private fun sourceKey(source: String): String =
        MessageDigest.getInstance("SHA-256").digest(source.toByteArray()).joinToString("") { "%02x".format(it) }

    private companion object {
        const val STABILITY_MILLIS = 10_000L
    }
}

internal fun backupSignature(
    size: Long,
    modified: Long,
    checkActive: () -> Unit = {},
    source: () -> InputStream,
): String {
    if (size >= 0 && modified > 0) return "$size:$modified"
    val digest = MessageDigest.getInstance("SHA-256")
    source().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            checkActive()
            val count = input.read(buffer)
            if (count < 0) break
            if (count > 0) digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

internal fun backupParent(
    destination: String,
    relativeParent: String,
): String {
    val parts = listOf(destination.trim('/'), relativeParent.trim('/')).filter(String::isNotEmpty)
    val segments = parts.flatMap { it.split('/') }
    require(segments.size <= 64 && segments.sumOf(String::length) <= 4096) { "The backup folder path is too long." }
    require(
        segments.all { part ->
            part.isNotEmpty() &&
                part.length <= 255 &&
                part !in setOf(".", "..") &&
                part.none { it == '\\' || it.isISOControl() }
        },
    ) { "The backup folder path is invalid." }
    return parts.joinToString("/", prefix = "/")
}

/** Historical outcomes must not suppress discovery of a changed local source. */
internal fun eu.opencloud.android.next.core.database.TransferEntity.blocksBackupScan(
    destinationSpace: String,
    source: String,
    destination: String,
): Boolean =
    direction == "UPLOAD" &&
        state in setOf("QUEUED", "RUNNING", "RETRY") &&
        spaceId == destinationSpace &&
        sourceUri == source &&
        destinationPath == destination
