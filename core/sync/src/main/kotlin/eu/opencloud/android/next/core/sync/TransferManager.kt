package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.util.UUID
import java.util.concurrent.TimeUnit

class TransferManager(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
    private val workManager: WorkManager = WorkManager.getInstance(context),
    private val clock: AppClock = SystemAppClock,
    private val sharedQueue: SharedDownloadQueue? = null,
) {
    private val mutationOperations =
        TransferMutationOperations(context, store, ::refreshAfterMutation)
    private val localCopies = LocalCopyOperations(context, store, workManager)

    private suspend fun refreshAfterMutation(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ) {
        store.queueFolderRefresh(accountId, spaceId, parentId)
        reconcileDiscovery()
    }

    suspend fun enqueueSharedDownload(
        request: SharedDownloadRequest,
        offlinePin: Boolean,
    ): TransferEntity {
        val accepted = sharedDownloads().enqueue(request, UUID.randomUUID().toString(), offlinePin, clock.epochMillis())
        enqueueDownloadWork(accepted)
        return requireNotNull(store.transfer(accepted.id))
    }

    private fun sharedDownloads() = sharedQueue ?: SharedDownloadQueue.create(context)

    suspend fun enqueueSharedUpload(
        destination: SharedFolderRequest,
        source: Uri,
        backup: eu.opencloud.android.next.core.database.FolderBackupEntity? = null,
    ): String {
        require(source.scheme == "content") { "Choose a readable local file." }
        val metadata = sourceMetadata(source)
        val name = metadata.name.requireValidSegment()
        val now = clock.epochMillis()
        val transfer =
            TransferEntity(
                id = UUID.randomUUID().toString(),
                accountId = destination.account,
                spaceId = destination.scope,
                resourceId = destination.remoteId,
                direction = "UPLOAD",
                sourceUri = source.toString(),
                destinationPath = destination.path.trimEnd('/') + "/" + name,
                displayName = name,
                mimeType = metadata.mimeType,
                bytesTotal = metadata.size,
                locationKind = "SHARED_FOLDER",
                createdAtEpochMillis = now,
                updatedAtEpochMillis = now,
            )
        val accepted = IncomingFolderUploadQueue.create(context).enqueue(destination, transfer, backup)
        enqueueUploadWork(accepted)
        return accepted.id
    }

    suspend fun enqueueUpload(
        accountId: String,
        spaceId: String,
        parentPath: String?,
        source: Uri,
        backup: eu.opencloud.android.next.core.database.FolderBackupEntity? = null,
    ): String {
        require(
            backup?.deleteAfterUpload != true,
        ) { "Source deletion is unavailable until upload verification is complete." }
        require(source.scheme == "content" || source.scheme == "file") { "Choose a readable local file." }
        val metadata = sourceMetadata(source)
        val name = metadata.name.requireValidSegment()
        val destination = "${parentPath?.trimEnd('/').orEmpty()}/$name"
        val now = clock.epochMillis()
        val transfer =
            TransferEntity(
                id = UUID.randomUUID().toString(),
                accountId = accountId,
                spaceId = spaceId,
                resourceId = null,
                direction = TransferDirection.UPLOAD.name,
                sourceUri = source.toString(),
                destinationPath = destination,
                displayName = name,
                mimeType = metadata.mimeType,
                bytesTotal = metadata.size,
                deleteSourceAfterSuccess = false,
                createdAtEpochMillis = now,
                updatedAtEpochMillis = now,
            )
        val accepted =
            if (backup == null) {
                store.enqueueTransfer(transfer)
            } else {
                eu.opencloud.android.next.core.database
                    .BackupScanStore(
                        FileBrowserDatabase.create(context),
                    ).enqueue(backup, transfer)
            }
        enqueueUploadWork(accepted)
        return accepted.id
    }

    suspend fun enqueueDownload(
        resource: ResourceEntity,
        offlinePin: Boolean,
    ): String {
        require(resource.kind.name == "FILE") { "Only files can be downloaded." }
        val now = clock.epochMillis()
        val transfer =
            TransferEntity(
                id = UUID.randomUUID().toString(),
                accountId = resource.accountId,
                spaceId = resource.spaceId,
                resourceId = resource.remoteId,
                direction = TransferDirection.DOWNLOAD.name,
                sourceUri = null,
                destinationPath = resource.path,
                displayName = resource.name,
                mimeType = resource.mimeType,
                bytesTotal = resource.sizeBytes,
                offlinePin = offlinePin,
                createdAtEpochMillis = now,
                updatedAtEpochMillis = now,
            )
        val accepted = store.enqueueTransfer(transfer)
        enqueueDownloadWork(accepted)
        return accepted.id
    }

    suspend fun ensureOfflineDownload(resource: ResourceEntity) {
        val current = store.resource(resource.accountId, resource.spaceId, resource.remoteId) ?: return
        if (cachedDownload(context, current) == null && store.blockedDownload(current) == null) {
            enqueueDownload(current, false)
        }
    }

    suspend fun makeAvailableOffline(resource: ResourceEntity) {
        store.setOfflinePinned(resource, true)
        if (resource.kind.name == "FOLDER") {
            val request =
                OneTimeWorkRequestBuilder<OfflineSyncWorker>()
                    .setInputData(
                        workDataOf(
                            OfflineSyncWorker.ACCOUNT_ID to resource.accountId,
                            OfflineSyncWorker.SPACE_ID to resource.spaceId,
                            OfflineSyncWorker.RESOURCE_ID to resource.remoteId,
                        ),
                    ).setConstraints(networkConstraints())
                    .addTag(accountWorkTag(resource.accountId))
                    .build()
            workManager.enqueueUniqueWork(
                "offline-${resource.accountId}-${resource.spaceId}-${resource.remoteId}",
                ExistingWorkPolicy.REPLACE,
                request,
            )
        } else {
            val current = store.resource(resource.accountId, resource.spaceId, resource.remoteId) ?: return
            if (cachedDownload(context, current) == null) enqueueDownload(current, true)
        }
    }

    suspend fun removeAllLocalCopies(accountId: String) = localCopies.removeAll(accountId)

    suspend fun removeLocalCopy(
        resource: ResourceEntity,
        requireSameCopy: Boolean = false,
    ) = localCopies.remove(resource, requireSameCopy)

    suspend fun ensureBackupDestination(
        accountId: String,
        spaceId: String,
        path: String,
    ) {
        require(!FileBrowserDatabase.create(context).vaultExclusionDao().denies(accountId, spaceId, path, true)) {
            "Encrypted vault locations are unavailable."
        }
        val account = requireNotNull(store.account(accountId))
        val space = requireNotNull(store.space(accountId, spaceId))
        require(account.isActive && !space.isDisabled && !space.isDeleted) { "The backup location is unavailable." }
        val root = webDavRoot(space)
        val http = TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl)
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val created =
            withRequestCancellation(
                cancelRequests = { http.dispatcher.cancelAll() },
                isOwned = {
                    val currentAccount = store.account(accountId)
                    val currentSpace = store.space(accountId, spaceId)
                    val available = currentSpace != null && !currentSpace.isDisabled && !currentSpace.isDeleted
                    currentAccount?.isActive == true &&
                        available &&
                        !FileBrowserDatabase.create(context).vaultExclusionDao().denies(accountId, spaceId, path, true)
                },
            ) {
                val coroutine = kotlinx.coroutines.currentCoroutineContext()
                ensureBackupCollections(root, path, http, authorization) { coroutine.ensureActive() }
            }
        if (created) {
            store.queueFolderRefresh(accountId, spaceId, null)
            reconcileDiscovery()
        }
    }

    suspend fun createFolder(
        accountId: String,
        spaceId: String,
        parentId: String?,
        name: String,
    ) = mutationOperations.createFolder(accountId, spaceId, parentId, name)

    fun refreshAccount(accountId: String): UUID {
        val request =
            OneTimeWorkRequestBuilder<AccountDiscoveryWorker>()
                .setInputData(
                    workDataOf(
                        AccountDiscoveryWorker.ACCOUNT_ID to accountId,
                    ),
                ).setConstraints(networkConstraints())
                .addTag(accountWorkTag(accountId))
                .build()
        workManager.enqueueUniqueWork("discover-$accountId", ExistingWorkPolicy.REPLACE, request)
        return request.id
    }

    fun refreshFolder(
        accountId: String,
        spaceId: String,
        folderId: String?,
    ): UUID {
        val request =
            OneTimeWorkRequestBuilder<FolderDiscoveryWorker>()
                .setInputData(
                    workDataOf(
                        FolderDiscoveryWorker.ACCOUNT_ID to accountId,
                        FolderDiscoveryWorker.SPACE_ID to spaceId,
                        FolderDiscoveryWorker.FOLDER_ID to folderId,
                    ),
                ).setConstraints(networkConstraints())
                .addTag(accountWorkTag(accountId))
                .build()
        workManager.enqueueUniqueWork(
            "folder-$accountId-$spaceId-${folderId ?: "root"}",
            ExistingWorkPolicy.REPLACE,
            request,
        )
        return request.id
    }

    suspend fun retryConflict(
        transfer: TransferEntity,
        overwrite: Boolean,
        keepBoth: Boolean = false,
    ) {
        require(transfer.direction == "UPLOAD" && transfer.state == "CONFLICT")
        require(overwrite != keepBoth) { "Choose either replace or keep both." }
        require(transfer.locationKind != "SHARED_FOLDER" || !overwrite) { "Shared uploads only support keep both." }
        val destination = if (keepBoth) conflictCopyPath(transfer.destinationPath) else transfer.destinationPath
        val reset =
            transfer.copy(
                destinationPath = destination,
                displayName = destination.substringAfterLast('/'),
                state = TransferState.QUEUED.name,
                error = null,
                errorCode = null,
                notBeforeEpochMillis = 0,
                attemptCount = 0,
                overwrite = overwrite,
                bytesTransferred = 0,
                verificationPending = false,
                expectedETag = null,
                verifiedETag = null,
                tusUrl = null,
                tusOffset = 0,
                workId = UUID.randomUUID().toString(),
                updatedAtEpochMillis = clock.epochMillis(),
            )
        val retried =
            if (transfer.locationKind == "SHARED_FOLDER") {
                IncomingFolderUploadQueue.create(context).retry(transfer, reset)
            } else {
                store.retryTransfer(transfer, reset)
            }
        retried?.let { enqueueUploadWork(it) }
    }

    suspend fun retry(transfer: TransferEntity) {
        require(
            transfer.state in
                setOf(
                    TransferState.FAILED.name,
                    TransferState.CANCELLED.name,
                    TransferState.RETRY.name,
                ),
        ) {
            "Only failed, cancelled, or waiting transfers can be retried."
        }
        val reset =
            transfer.copy(
                state = TransferState.QUEUED.name,
                error = null,
                errorCode = null,
                notBeforeEpochMillis = 0,
                attemptCount = 0,
                verificationPending = transfer.requiresUploadVerificationOnRetry(),
                workId = UUID.randomUUID().toString(),
                updatedAtEpochMillis = clock.epochMillis(),
            )
        val retried =
            if (transfer.locationKind == "SHARED_FOLDER") {
                if (transfer.direction == "UPLOAD") {
                    IncomingFolderUploadQueue.create(context).retry(transfer, reset)
                } else {
                    sharedDownloads().retry(transfer, requireNotNull(reset.workId), clock.epochMillis())
                }
            } else {
                store.retryTransfer(transfer, reset)
            }
        retried?.let { accepted ->
            if (accepted.direction == TransferDirection.UPLOAD.name) {
                enqueueUploadWork(accepted)
            } else {
                enqueueDownloadWork(accepted)
            }
        }
    }

    suspend fun cancel(transfer: TransferEntity) {
        store.cancelTransfer(transfer.id)
        workManager.cancelUniqueWork("transfer-${transfer.id}")
    }

    suspend fun clearHistory(accountId: String) = store.clearTransferHistory(accountId)

    suspend fun clearAll(
        accountId: String,
        transfers: List<TransferEntity>,
    ) {
        transfers.mapNotNull(TransferEntity::workId).forEach { workId ->
            runCatching { workManager.cancelWorkById(UUID.fromString(workId)) }
        }
        store.clearTransfers(accountId)
    }

    suspend fun cancelConflict(transfer: TransferEntity) {
        store.updateTransfer(
            transfer.copy(
                state = TransferState.CANCELLED.name,
                error = null,
                errorCode = null,
                notBeforeEpochMillis = 0,
                attemptCount = 0,
                updatedAtEpochMillis = clock.epochMillis(),
            ),
        )
    }

    suspend fun saveBackup(configuration: eu.opencloud.android.next.core.database.FolderBackupEntity) {
        require(
            configuration.dateOrganization == "NONE" ||
                configuration.dateOrganization == "YEAR_MONTH" ||
                isValidBackupDateTemplate(configuration.dateOrganization),
        ) { "Choose a valid date folder pattern." }
        if (configuration.destinationKind == "SHARED_FOLDER") {
            SharedUploadDestinationResolver.create(context).prepare(configuration.sharedRequest())
        }
        store.saveBackup(configuration)
        scheduleBackups()
        scanBackupsNow()
    }

    fun scanBackupsNow() {
        val immediate =
            OneTimeWorkRequestBuilder<FolderBackupScanWorker>()
                .setConstraints(backupConstraints(BuildConfig.DEBUG))
                .build()
        workManager.enqueueUniqueWork(BACKUP_SCAN_WORK, ExistingWorkPolicy.REPLACE, immediate)
    }

    fun scheduleBackups() {
        val request =
            PeriodicWorkRequestBuilder<FolderBackupScanWorker>(
                15,
                TimeUnit.MINUTES,
            ).setConstraints(backupConstraints(BuildConfig.DEBUG)).build()
        workManager.enqueueUniquePeriodicWork(BACKUP_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    suspend fun reconcile() {
        reconcileDiscovery()
        store.pendingTransfers().forEach { transfer ->
            if (transfer.direction ==
                TransferDirection.UPLOAD.name
            ) {
                enqueueUploadWork(transfer)
            } else {
                enqueueDownloadWork(transfer)
            }
        }
    }

    suspend fun reconcileDiscovery() {
        var after = ""
        while (true) {
            val page = store.pendingDiscoveries(after)
            if (page.isEmpty()) return
            page.forEach { pending ->
                val request =
                    OneTimeWorkRequestBuilder<FolderDiscoveryWorker>()
                        .setInputData(
                            workDataOf(
                                FolderDiscoveryWorker.ACCOUNT_ID to pending.accountId,
                                FolderDiscoveryWorker.SPACE_ID to pending.spaceId,
                                FolderDiscoveryWorker.FOLDER_ID to pending.folderKey.ifEmpty { null },
                                FolderDiscoveryWorker.REVISION to pending.revision,
                            ),
                        ).setConstraints(networkConstraints())
                        .addTag(accountWorkTag(pending.accountId))
                        .build()
                workManager
                    .enqueueUniqueWork(
                        "confirmed-discovery-${pending.revision}",
                        ExistingWorkPolicy.KEEP,
                        request,
                    ).result
                    .get()
                if (store.pendingDiscovery(pending.revision) == null) workManager.cancelWorkById(request.id)
            }
            after = page.last().revision
        }
    }

    suspend fun setFavorite(
        resource: ResourceEntity,
        favorite: Boolean,
    ) = mutationOperations.setFavorite(resource, favorite)

    suspend fun delete(resource: ResourceEntity) = mutationOperations.delete(resource)

    suspend fun renameFile(
        resource: ResourceEntity,
        name: String,
    ) = mutationOperations.renameFile(resource, name)

    suspend fun cancelAccountWork(accountId: String) {
        store
            .activeTransfers(accountId)
            .mapNotNull { it.workId }
            .mapNotNull { workId ->
                runCatching { UUID.fromString(workId) }.getOrNull()
            }.forEach(workManager::cancelWorkById)
        workManager.cancelAllWorkByTag(accountWorkTag(accountId))
    }

    fun scheduleCleanup() {
        scheduleExcludedCacheCleanup(context)
        workManager.enqueueUniqueWork(
            STARTUP_CLEANUP_WORK,
            ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<CacheCleanupWorker>().build(),
        )
        val request = PeriodicWorkRequestBuilder<CacheCleanupWorker>(1, TimeUnit.HOURS).build()
        workManager.enqueueUniquePeriodicWork(CLEANUP_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
        val offline =
            PeriodicWorkRequestBuilder<OfflineSyncWorker>(
                15,
                TimeUnit.MINUTES,
            ).setConstraints(networkConstraints()).build()
        workManager.enqueueUniquePeriodicWork(OFFLINE_WORK, ExistingPeriodicWorkPolicy.UPDATE, offline)
        scheduleBackups()
    }

    private suspend fun enqueueUploadWork(transfer: TransferEntity) = enqueueTransferWork(transfer)

    private suspend fun enqueueDownloadWork(transfer: TransferEntity) = enqueueTransferWork(transfer)

    private suspend fun enqueueTransferWork(transfer: TransferEntity) {
        schedulingMutex.withLock {
            val current = store.transfer(transfer.id) ?: return@withLock
            if (current.state !in setOf("QUEUED", "RUNNING", "RETRY")) return@withLock
            val name = "transfer-${current.id}"
            val existing = workManager.getWorkInfosForUniqueWork(name).get().firstOrNull { !it.state.isFinished }
            val matchesIntent = current.workId == null || existing?.id?.toString() == current.workId
            val obsoleteConstraint =
                existing?.constraints?.requiredNetworkType == NetworkType.CONNECTED &&
                    existing.state != androidx.work.WorkInfo.State.RUNNING
            if (existing != null && matchesIntent && !obsoleteConstraint) {
                store.recordScheduledWork(current, existing.id.toString(), clock.epochMillis())
                return@withLock
            }
            val persistedId = current.workId?.let(UUID::fromString)
            val requestId = persistedId?.takeIf { workManager.getWorkInfoById(it).get() == null } ?: UUID.randomUUID()
            val builder =
                if (current.direction == TransferDirection.UPLOAD.name) {
                    OneTimeWorkRequestBuilder<UploadWorker>()
                } else {
                    OneTimeWorkRequestBuilder<DownloadWorker>()
                }
            val request =
                builder
                    .setId(requestId)
                    .setInputData(workDataOf(TransferWorker.TRANSFER_ID to current.id))
                    .setInitialDelay(
                        (current.notBeforeEpochMillis - clock.epochMillis()).coerceIn(0, TimeUnit.DAYS.toMillis(1)),
                        TimeUnit.MILLISECONDS,
                    ).setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                    .setConstraints(constraintsForTransfer(current))
                    .addTag(accountWorkTag(current.accountId))
                    .build()
            if (!store.recordScheduledWork(current, request.id.toString(), clock.epochMillis())) return@withLock
            // A different active ID belongs to the superseded attempt. Durable intent wins.
            workManager.enqueueUniqueWork(name, ExistingWorkPolicy.REPLACE, request).result.get()
            val latest = store.transfer(current.id)
            if (latest == null ||
                latest.state == TransferState.CANCELLED.name ||
                latest.workId != request.id.toString()
            ) {
                workManager.cancelWorkById(request.id)
            }
        }
    }

    private suspend fun constraintsForTransfer(transfer: TransferEntity): Constraints {
        val pairs =
            store.enabledBackups().filter { pair ->
                transfer.direction == TransferDirection.UPLOAD.name &&
                    pair.accountId == transfer.accountId &&
                    pair.spaceId == transfer.spaceId &&
                    transfer.sourceUri?.startsWith(pair.sourceTreeUri.trimEnd('/') + "/document/") == true &&
                    transfer.destinationPath.startsWith(pair.destinationPath.trimEnd('/') + "/")
            }
        return Constraints
            .Builder()
            .setRequiredNetworkType(if (pairs.any { it.wifiOnly }) NetworkType.UNMETERED else NetworkType.NOT_REQUIRED)
            .setRequiresCharging(pairs.any { it.chargingOnly })
            .build()
    }

    private fun sourceMetadata(uri: Uri): SourceMetadata {
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "upload"
        var size = -1L
        if (uri.scheme == "content") {
            queryContentMetadata(uri)?.let { metadata ->
                name = metadata.name ?: name
                size = metadata.size ?: size
            }
        }
        if (size < 0) {
            size =
                try {
                    context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
                } catch (_: java.io.FileNotFoundException) {
                    -1L // Some providers support streams but cannot expose an asset descriptor.
                }
        }
        return SourceMetadata(name, context.contentResolver.getType(uri), size)
    }

    private fun queryContentMetadata(uri: Uri): ContentMetadata? =
        context.contentResolver
            .query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null,
                null,
                null,
            )?.use { cursor ->
                if (!cursor.moveToFirst()) return@use null
                ContentMetadata(
                    name = cursor.getString(0),
                    size = if (cursor.isNull(1)) null else cursor.getLong(1),
                )
            }

    private data class SourceMetadata(
        val name: String,
        val mimeType: String?,
        val size: Long,
    )

    private data class ContentMetadata(
        val name: String?,
        val size: Long?,
    )

    private companion object {
        val schedulingMutex = Mutex()
        const val CLEANUP_WORK = "opencloud-cache-cleanup"
        const val STARTUP_CLEANUP_WORK = "opencloud-startup-cache-cleanup"
        const val OFFLINE_WORK = "opencloud-offline-sync"
        const val BACKUP_WORK = "opencloud-folder-backups"
        const val BACKUP_SCAN_WORK = "opencloud-folder-backup-scan"
    }
}

fun accountWorkTag(accountId: String) = "opencloud-account-$accountId"

internal fun ensureBackupCollections(
    root: String,
    path: String,
    http: OkHttpClient,
    authorization: String,
    checkActive: () -> Unit = {},
): Boolean {
    val safePath = backupParent(path, "")
    safePath.split('/').filter(String::isNotBlank).forEach { it.requireValidSegment() }
    val dav =
        eu.opencloud.android.next.core.network
            .DavOperationClient(http)
    val client = TransferClient(http)
    var created = false
    destinationCollectionPaths("${safePath.trimEnd('/')}/placeholder").forEach { collection ->
        val url = root.mutationChildUrl(collection)
        checkActive()
        var metadata = dav.stat(url, authorization)
        if (metadata == null) {
            checkActive()
            client.createCollection(url, authorization)
            created = true
            checkActive()
            metadata = dav.stat(url, authorization)
        }
        require(metadata?.folder == true) { "The backup destination is not a folder." }
    }
    return created
}

// WorkManager CONNECTED requires internet validation on modern Android; a LAN server needs only a route.
// Workers probe connectivity and use the existing retry/backoff policy when the server is unreachable.
private fun networkConstraints() = Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build()

internal fun String.mutationChildUrl(path: String): String =
    toHttpUrl()
        .newBuilder()
        .apply {
            path
                .trim('/')
                .split('/')
                .filter(String::isNotBlank)
                .forEach(::addPathSegment)
        }.build()
        .toString()

internal fun backupConstraints(
    @Suppress("UNUSED_PARAMETER") debug: Boolean,
): Constraints =
    Constraints
        .Builder()
        .setRequiredNetworkType(NetworkType.NOT_REQUIRED)
        .build()

internal fun conflictCopyPath(path: String): String {
    val name = path.substringAfterLast('/')
    val parent = path.substringBeforeLast('/', "")
    val dot = name.lastIndexOf('.').takeIf { it > 0 } ?: name.length
    val extension = name.substring(dot)
    val stem = name.substring(0, dot)
    val numberedCopy = Regex("^(.*) \\((\\d+)\\)$").matchEntire(stem)
    val originalStem = numberedCopy?.groupValues?.get(1) ?: stem
    val nextNumber =
        (numberedCopy?.groupValues?.get(2)?.toBigIntegerOrNull() ?: java.math.BigInteger.ZERO) +
            java.math.BigInteger.ONE
    val separator = if (parent.isEmpty()) "/" else "$parent/"
    return "$separator$originalStem ($nextNumber)$extension"
}

internal fun String.requireValidSegment(): String {
    require(isNotBlank() && none { it == '/' || it == '\\' || it.isISOControl() } && this != "." && this != "..") {
        "The selected file has an invalid name."
    }
    return this
}
