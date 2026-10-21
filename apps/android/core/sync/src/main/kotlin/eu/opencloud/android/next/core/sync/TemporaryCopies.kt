package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first

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
        store.observeOffline(account.id).first().forEach { resource ->
            currentCoroutineContext().ensureActive()
            val file =
                validatedCachedFile(
                    resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                    resource.localPath,
                    resource.sizeBytes,
                )
            if (file != null && file.lastModified() < cutoff) {
                PrivateCacheUse.ifUnused(file) {
                    store.expireTemporaryCopy(resource) { file.lastModified() < cutoff && file.delete() }
                }
            }
        }
    }
}

/** Removes temporary copies across accounts, preserving offline roots and active downloads. */
suspend fun clearTemporaryCopies(context: Context): Int {
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
}

internal suspend fun clearTemporaryCopies(
    context: Context,
    store: FileBrowserStore,
): Int {
    var removed = 0
    store.activeAccounts().forEach { account ->
        store.observeOffline(account.id).first().forEach { resource ->
            currentCoroutineContext().ensureActive()
            val file =
                validatedCachedFile(
                    resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                    resource.localPath,
                    resource.sizeBytes,
                )
            if (file != null &&
                PrivateCacheUse.ifUnused(file) {
                    store.expireTemporaryCopy(resource) { file.delete() }
                }
            ) {
                removed++
            }
        }
    }
    return removed
}
