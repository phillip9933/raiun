package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.model.cacheIdentity
import java.io.File
import java.util.UUID

internal fun downloadAttemptTargetName(transferId: String): String =
    "download-attempt-${cacheIdentity(transferId)}.${UUID.randomUUID()}"

/**
 * Reclaims ordinary download files after an attempt has released its writer lease. The cache gate
 * prevents another writer or reader from acquiring a file between the reference check and deletion.
 */
internal suspend fun cleanupUnpublishedDownloadAttempt(
    store: FileBrowserStore,
    transfer: TransferEntity,
    target: File,
    partial: File,
    validator: File,
) {
    removeIfUnreferenced(store, target)

    val current = store.transfer(transfer.id)
    val cancelledOrRevoked =
        current == null ||
            current.workId != transfer.workId ||
            current.state == TransferState.CANCELLED.name
    if (cancelledOrRevoked) {
        removeIfUnreferenced(store, partial)
        removeIfUnreferenced(store, validator)
    }
}

private suspend fun removeIfUnreferenced(
    store: FileBrowserStore,
    file: File,
) {
    PrivateCacheUse.removeIfUnused(file) { !store.referencesCache(file.absolutePath) }
}
