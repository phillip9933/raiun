package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.LocalCopyRemovalChangedException
import eu.opencloud.android.next.core.database.LocalCopyRemovalDecision
import eu.opencloud.android.next.core.database.LocalCopyRemovalRow
import eu.opencloud.android.next.core.database.LocalCopyRemovalScope
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TemporaryCopyKey
import eu.opencloud.android.next.core.database.localCopyRemovals
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.UUID

/** Explicit selection removal shares the cache-use exclusion gate with ordinary readers and publishers. */
internal class LocalCopyOperations(
    private val context: Context,
    store: FileBrowserStore,
    private val workManager: WorkManager,
) {
    private val removals = store.localCopyRemovals()
    private val staging get() = File(context.noBackupFilesDir, "ordinary-removal-inventory")

    suspend fun removeAll(accountId: String) =
        storageBoundary {
            val scope = removals.captureAll(accountId, staging) ?: return@storageBoundary
            scope.use {
                cancelDownloads(scope)
                var after: TemporaryCopyKey? = null
                var retainedCount = 0L
                while (true) {
                    currentCoroutineContext().ensureActive()
                    val page = removals.page(scope, after)
                    if (page.isEmpty()) break
                    for (row in page) {
                        currentCoroutineContext().ensureActive()
                        if (!removeCaptured(scope, row)) retainedCount = Math.addExact(retainedCount, 1L)
                    }
                    val last = page.last().resource
                    after = TemporaryCopyKey(last.spaceId, last.remoteId)
                }
                if (retainedCount != 0L) retained()
            }
        }

    suspend fun remove(
        resource: ResourceEntity,
        requireSameCopy: Boolean = false,
    ) = storageBoundary {
        val scope = removals.captureOne(resource, requireSameCopy, staging) ?: return@storageBoundary
        scope.use {
            val row = removals.page(scope).single()
            if (!removeCaptured(scope, row, cancelFirst = true)) retained()
        }
    }

    private suspend fun removeCaptured(
        scope: LocalCopyRemovalScope,
        row: LocalCopyRemovalRow,
        cancelFirst: Boolean = false,
    ): Boolean =
        if (!row.removeCopy) {
            if (cancelFirst) cancelDownloads(scope)
            removals.remove(scope, row) { true } == LocalCopyRemovalDecision.Applied
        } else {
            val file = matchingCandidate(row.resource)
            file != null && removeFile(scope, row, file, cancelFirst)
        }

    private fun matchingCandidate(resource: ResourceEntity): File? =
        ownedCandidate(resource)?.takeIf { matchesCopy(it, resource.sizeBytes) }

    private suspend fun removeFile(
        scope: LocalCopyRemovalScope,
        row: LocalCopyRemovalRow,
        file: File,
        cancelFirst: Boolean,
    ): Boolean =
        PrivateCacheUse.ifUnused(file) {
            if (cancelFirst) cancelDownloads(scope)
            removals.remove(scope, row) {
                val checked = ownedCandidate(row.resource)
                if (checked != file || !matchesCopy(file, row.resource.sizeBytes)) {
                    throw LocalCopyRemovalChangedException()
                }
                !Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS) || file.delete()
            } == LocalCopyRemovalDecision.Applied
        }

    private suspend fun cancelDownloads(scope: LocalCopyRemovalScope) {
        var after: String? = null
        while (true) {
            currentCoroutineContext().ensureActive()
            val page = removals.downloadPage(scope, after)
            if (page.isEmpty()) return
            for (transfer in page) {
                currentCoroutineContext().ensureActive()
                val work = removals.cancelDownload(scope, transfer.id)?.workId
                work?.let { runCatching { UUID.fromString(it) }.getOrNull() }?.let(workManager::cancelWorkById)
            }
            after = page.last().id
        }
    }

    @Suppress("ReturnCount") // Each fail-closed ownership/path preflight must stop before touching a different file.
    private fun ownedCandidate(resource: ResourceEntity): File? {
        val raw = resource.localPath?.let(::File) ?: return null
        val directory = resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId)
        val boundary =
            context.filesDir.absoluteFile
                .toPath()
                .normalize()
        var parent = directory.absoluteFile.toPath().normalize()
        while (parent != boundary && parent.startsWith(boundary)) {
            if (Files.isSymbolicLink(parent)) return null
            parent = parent.parent ?: return null
        }
        if (parent != boundary || Files.isSymbolicLink(raw.toPath())) return null
        val file = raw.canonicalFile
        return file.takeIf { it.parentFile == directory.canonicalFile }
    }

    private fun matchesCopy(
        file: File,
        size: Long,
    ): Boolean =
        !Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS) ||
            (Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) && file.length() == size)

    private suspend fun storageBoundary(action: suspend () -> Unit) {
        try {
            action()
        } catch (_: LocalCopyRemovalChangedException) {
            retained()
        } catch (_: IOException) {
            throw OpenCloudException(OpenCloudError.LocalCopyRemovalFailed)
        } catch (_: android.database.sqlite.SQLiteException) {
            throw OpenCloudException(OpenCloudError.LocalCopyRemovalFailed)
        }
    }

    private fun retained(): Nothing = throw OpenCloudException(OpenCloudError.LocalCopiesRetained)
}
