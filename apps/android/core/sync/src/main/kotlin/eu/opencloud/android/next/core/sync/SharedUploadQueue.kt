package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.cacheIdentity
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File

class SharedUploadQueue(
    private val context: Context,
) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(context))

    suspend fun enqueue(
        accountId: String,
        spaceId: String,
        parentPath: String,
        source: SharedUploadSource,
    ) {
        val destination = "${parentPath.trimEnd('/')}/${source.name}"
        val existing = store.transfer(source.id)
        if (existing != null) {
            check(existing.expectedETag == source.expectedETag && existing.resourceId == source.resourceId)
            check(
                existing.accountId == accountId &&
                    existing.spaceId == spaceId &&
                    existing.destinationPath == destination,
            ) {
                "Some files are already queued. Keep the same destination when retrying."
            }
        } else {
            val coroutine = currentCoroutineContext()
            val directory =
                File(context.noBackupFilesDir, "upload-sources/${cacheIdentity(accountId)}/${cacheIdentity(source.id)}")
            PrivateCacheUse.hold(uploadSourceFiles(directory) + source.payload) {
                val staged =
                    stageUploadSource(directory, source.payload.length(), { source.payload.inputStream() }, {
                        directory.usableSpace
                    }) { coroutine.ensureActive() }
                val now = System.currentTimeMillis()
                store.enqueueTransfer(
                    TransferEntity(
                        id = source.id,
                        accountId = accountId,
                        spaceId = spaceId,
                        resourceId = source.resourceId,
                        direction = "UPLOAD",
                        sourceUri = Uri.fromFile(staged).toString(),
                        destinationPath = destination,
                        displayName = source.name,
                        mimeType = source.mimeType,
                        bytesTotal = staged.length(),
                        expectedETag = source.expectedETag,
                        createdAtEpochMillis = now,
                        updatedAtEpochMillis = now,
                    ),
                )
            }
        }
        TransferManager(context, store).reconcile()
    }
}
