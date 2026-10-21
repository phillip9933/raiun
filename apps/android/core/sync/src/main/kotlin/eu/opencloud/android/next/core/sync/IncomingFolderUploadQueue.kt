package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.room.withTransaction
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Upload resourceId stores the selected destination folder; scopeId never becomes an ordinary drive ID. */
class IncomingFolderUploadQueue(
    private val database: FileBrowserDatabase,
    private val resolver: SharedUploadDestinationResolver,
) {
    private val transfers = database.transferDao()
    private val sharedCache = SharedFolderCacheStore(database)

    suspend fun enqueue(
        request: SharedFolderRequest,
        transfer: TransferEntity,
        backup: FolderBackupEntity? = null,
    ): TransferEntity {
        validate(transfer)
        require(transfer.state == "QUEUED" && transfer.workId == null && transfer.attemptCount == 0)
        require(transfer.accountId == request.account && transfer.spaceId == request.scope)
        require(transfer.resourceId == request.remoteId && parentPath(transfer) == request.path)
        val destination = resolver.prepare(request)
        return database.withTransaction {
            requireCurrent(destination, transfer.destinationPath)
            if (backup != null) {
                require(backup.enabled && database.folderBackupDao().findById(backup.id) == backup) {
                    "The backup configuration changed."
                }
                require(backup.destinationKind == "SHARED_FOLDER" && backup.accountId == request.account)
                require(backup.spaceId == request.scope && backup.sharedShareId == request.share)
                require(
                    transfer.destinationPath.startsWith(backup.destinationPath.trimEnd('/') + "/") ||
                        backup.destinationPath == "/",
                )
            }
            val duplicate =
                transfers.findActiveUpload(
                    transfer.accountId,
                    transfer.spaceId,
                    requireNotNull(transfer.sourceUri),
                    transfer.destinationPath,
                )
            if (duplicate != null) {
                require(duplicate.locationKind == "SHARED_FOLDER" && duplicate.resourceId == request.remoteId)
                duplicate
            } else {
                transfers.insert(transfer)
                transfer
            }
        }
    }

    suspend fun prepare(transfer: TransferEntity): PreparedSharedUploadDestination {
        validate(transfer)
        val scope =
            database.sharedFolderCacheDao().scope(transfer.accountId, transfer.spaceId)
                ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val request =
            SharedFolderRequest(
                transfer.accountId,
                scope.shareId,
                transfer.spaceId,
                requireNotNull(transfer.resourceId),
                parentPath(transfer),
            )
        return resolver.prepare(request).also { requireCurrent(it, transfer.destinationPath) }
    }

    suspend fun retry(
        expected: TransferEntity,
        replacement: TransferEntity,
    ): TransferEntity? {
        require(replacement.id == expected.id && replacement.sourceUri == expected.sourceUri)
        require(parentPath(replacement) == parentPath(expected) && replacement.resourceId == expected.resourceId)
        val destination = prepare(expected)
        validate(replacement)
        require(replacement.accountId == expected.accountId && replacement.spaceId == expected.spaceId)
        return database.withTransaction {
            requireCurrent(destination, replacement.destinationPath)
            val duplicate =
                transfers.findActiveUpload(
                    expected.accountId,
                    expected.spaceId,
                    requireNotNull(expected.sourceUri),
                    expected.destinationPath,
                )
            if (duplicate != null) null else transfers.retry(expected, replacement)
        }
    }

    suspend fun complete(
        expected: TransferEntity,
        destination: PreparedSharedUploadDestination,
        verifiedETag: String?,
        now: Long,
    ): Boolean =
        database.withTransaction {
            requireCurrent(destination, expected.destinationPath)
            val current = transfers.findById(expected.id)
            val owned = current?.workId == expected.workId && current?.state == "RUNNING"
            if (current == null || !owned) return@withTransaction false
            validate(current)
            require(current.destinationPath == expected.destinationPath && current.sourceUri == expected.sourceUri)
            require(current.accountId == destination.request.account && current.spaceId == destination.request.scope)
            require(
                current.resourceId == destination.request.remoteId && parentPath(current) == destination.request.path,
            )
            transfers.updateActive(
                current.copy(
                    state = "SUCCEEDED",
                    bytesTransferred = current.bytesTotal,
                    verifiedETag = verifiedETag,
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    updatedAtEpochMillis = now,
                ),
            )
        }

    private suspend fun requireCurrent(
        destination: PreparedSharedUploadDestination,
        destinationPath: String? = null,
    ) {
        currentCoroutineContext().ensureActive()
        val page = destination.page
        val scope = database.sharedFolderCacheDao().scope(page.location.accountId, page.location.scopeId)
        val parentAllowed =
            sharedCache.isAllowed(
                page.checked.lease,
                page.location.binding(),
                destination.request.path,
                requireCachedPage = true,
            )
        val targetAllowed =
            destinationPath == null ||
                sharedCache.isAllowed(page.checked.lease, page.location.binding(), destinationPath)
        if (scope != page.location.binding() ||
            !parentAllowed ||
            !targetAllowed
        ) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun validate(transfer: TransferEntity) {
        require(transfer.direction == "UPLOAD" && transfer.locationKind == "SHARED_FOLDER")
        require(!transfer.overwrite && !transfer.deleteSourceAfterSuccess && transfer.expectedETag == null)
        require(transfer.tusUrl == null && !transfer.sourceUri.isNullOrBlank())
        requireSharedPath(transfer.destinationPath)
        require(
            transfer.destinationPath != "/" && transfer.displayName == transfer.destinationPath.substringAfterLast('/'),
        )
        transfer.displayName.requireValidSegment()
    }

    private fun parentPath(transfer: TransferEntity) = transfer.destinationPath.substringBeforeLast('/').ifEmpty { "/" }

    companion object {
        fun create(context: Context) =
            IncomingFolderUploadQueue(
                FileBrowserDatabase.create(context),
                SharedUploadDestinationResolver.create(context),
            )
    }
}
