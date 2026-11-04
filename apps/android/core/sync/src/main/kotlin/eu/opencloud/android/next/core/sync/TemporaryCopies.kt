package eu.opencloud.android.next.core.sync

import android.content.Context
import android.database.sqlite.SQLiteException
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TemporaryCopyKey
import eu.opencloud.android.next.core.database.TemporaryCopyScope
import eu.opencloud.android.next.core.database.temporaryCopies
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.IOException

/** Deliberately offline files and their descendants are excluded inside the database transaction. */
internal suspend fun expireTemporaryCopies(
    context: Context,
    store: FileBrowserStore,
    hours: Int,
    now: Long = System.currentTimeMillis(),
) {
    if (hours <= 0) return
    val cutoff = now - hours * 3_600_000L
    store.activeAccounts().forEach { account ->
        forEachTemporaryCopy(context, store, account.id) { scope, resource ->
            currentCoroutineContext().ensureActive()
            val file =
                validatedCachedFile(
                    resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                    resource.localPath,
                    resource.sizeBytes,
                )
            if (file != null && file.lastModified() < cutoff) {
                PrivateCacheUse.ifUnused(file) {
                    store.temporaryCopies().expire(scope, resource) { file.lastModified() < cutoff && file.delete() }
                }
            }
        }
    }
}

/** Removes temporary copies across accounts, preserving offline roots and active downloads. */
suspend fun clearTemporaryCopies(context: Context): Int {
    try {
        val ordinary =
            clearTemporaryCopies(
                context,
                FileBrowserStore(
                    eu.opencloud.android.next.core.database.FileBrowserDatabase
                        .create(context),
                ),
            )
        val shared =
            SharedDownloadMaintenance(
                eu.opencloud.android.next.core.database.FileBrowserDatabase
                    .create(context),
                context.filesDir,
            ).clearTemporary()
        return ordinary + shared
    } catch (failure: SQLiteException) {
        // Settings already presents I/O failures; database disk errors must not escape its coroutine.
        throw IOException("Temporary copies could not be removed from local storage.", failure)
    }
}

internal suspend fun clearTemporaryCopies(
    context: Context,
    store: FileBrowserStore,
): Int {
    var removed = 0
    store.activeAccounts().forEach { account ->
        forEachTemporaryCopy(context, store, account.id) { scope, resource ->
            currentCoroutineContext().ensureActive()
            val file =
                validatedCachedFile(
                    resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                    resource.localPath,
                    resource.sizeBytes,
                )
            if (file != null &&
                PrivateCacheUse.ifUnused(file) {
                    store.temporaryCopies().expire(scope, resource) { file.delete() }
                }
            ) {
                removed++
            }
        }
    }
    return removed
}

/** The captured rows are immutable; deletion cannot shift pages or admit newly downloaded copies. */
private suspend fun forEachTemporaryCopy(
    context: Context,
    store: FileBrowserStore,
    accountId: String,
    action: suspend (TemporaryCopyScope, ResourceEntity) -> Unit,
) {
    val directory = File(context.noBackupFilesDir, "ordinary-temp-inventory")
    val scope = store.temporaryCopies().capture(accountId, directory) ?: return
    scope.use {
        var after: TemporaryCopyKey? = null
        while (true) {
            currentCoroutineContext().ensureActive()
            val page = store.temporaryCopies().page(scope, after)
            if (page.isEmpty()) return
            for (resource in page) {
                currentCoroutineContext().ensureActive()
                action(scope, resource)
            }
            val last = page.last()
            after = TemporaryCopyKey(last.spaceId, last.remoteId)
        }
    }
}
