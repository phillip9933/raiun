package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.BatteryManager
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ListenableWorker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

class AccountDiscoveryWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            var favoriteRemaining = -1
            runCatching {
                val store = store()
                val accountId = requireNotNull(inputData.getString(ACCOUNT_ID))
                val account = requireNotNull(store.account(accountId))
                val httpClient = httpClient(account.serverUrl)
                val remote = RemoteDiscoveryClient(httpClient)
                val authorization = WorkerAuthorizationProvider(applicationContext).authorization(account)
                CapabilityRepository.get(applicationContext).refresh(account, authorization, store)
                val spaces =
                    SpaceRepository(store, LibreGraphSpacesClient(httpClient)).synchronize(
                        account.id,
                        account.serverUrl,
                        authorization,
                    )
                spaces.filterNot { it.isDeleted || it.isDisabled }.forEach { space ->
                    refreshFolder(FolderRefresh(store, remote, account.id, space, null, "/", authorization))
                }
                store.account(account.id)?.remoteSearchUrl?.let { endpoint ->
                    val token = store.beginSnapshot(account.id)
                    val roots =
                        spaces.filterNot { it.isDeleted || it.isDisabled }.associate {
                            it.driveId to
                                webDavRoot(it)
                        }
                    val rawFavorites =
                        eu.opencloud.android.next.core.network
                            .FavoriteSnapshotClient(httpClient)
                            .locations(endpoint, authorization, roots)
                    val exclusionDao = FileBrowserDatabase.create(applicationContext).vaultExclusionDao()
                    val exclusionSnapshot = exclusionDao.allForAccount(account.id)
                    val favorites = filterFavoriteLocations(account.id, rawFavorites, exclusionSnapshot)
                    favoriteRemaining =
                        FavoriteHydrator(
                            store,
                            isVaultExcluded = { owner, spaceId, path ->
                                exclusionDao.denies(owner, spaceId, path)
                            },
                            currentExclusions = exclusionDao::allForAccount,
                        ) { spaceId, parentId, path ->
                            val space = requireNotNull(spaces.find { it.driveId == spaceId })
                            refreshFolder(
                                FolderRefresh(store, remote, account.id, space, parentId, path, authorization),
                            )
                        }.hydrate(account.id, favorites)
                    if (!store.replaceFavoriteSnapshot(account.id, favorites.mapValues { it.value.keys }, token)) {
                        throw SupersededDiscovery()
                    }
                }
            }.fold(
                onSuccess = { Result.success(workDataOf(FAVORITE_REMAINING to favoriteRemaining)) },
                onFailure = { discoveryFailure("Account discovery", it) },
            ).also {
                schedulePendingExcludedCache(applicationContext)
                scheduleSharedDownloadCleanup(applicationContext)
            }
        }

    companion object {
        const val ACCOUNT_ID = "accountId"
        const val FAVORITE_REMAINING = "favoriteRemainingUpperBound"
    }
}

class FolderDiscoveryWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val revision = inputData.getString(REVISION)
            if (revision != null && store().pendingDiscovery(revision) == null) return@withContext Result.success()
            runCatching {
                val store = store()
                val accountId = requireNotNull(inputData.getString(ACCOUNT_ID))
                val spaceId = requireNotNull(inputData.getString(SPACE_ID))
                val folderId = inputData.getString(FOLDER_ID)
                val account = requireNotNull(store.account(accountId))
                val space = requireNotNull(store.space(accountId, spaceId))
                val path = folderId?.let { requireNotNull(store.resource(accountId, spaceId, it)).path } ?: "/"
                refreshFolder(
                    FolderRefresh(
                        store,
                        remote(account.serverUrl),
                        accountId,
                        space,
                        folderId,
                        path,
                        WorkerAuthorizationProvider(applicationContext).authorization(account),
                    ),
                )
                if (revision != null) store.acknowledgeDiscovery(revision)
            }.fold(onSuccess = { Result.success() }, onFailure = { discoveryFailure("Folder discovery", it) })
                .also { schedulePendingExcludedCache(applicationContext) }
        }

    companion object {
        const val ACCOUNT_ID = "accountId"
        const val SPACE_ID = "spaceId"
        const val FOLDER_ID = "folderId"
        const val REVISION = "confirmedDiscoveryRevision"
    }
}

class OfflineSyncWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            runCatching {
                val store = store()
                val queue =
                    eu.opencloud.android.next.core.database.OfflineTraversalStore(
                        FileBrowserDatabase.create(applicationContext),
                    )
                val resourceId = inputData.getString(RESOURCE_ID)
                if (resourceId != null) {
                    val accountId = requireNotNull(inputData.getString(ACCOUNT_ID))
                    val spaceId = requireNotNull(inputData.getString(SPACE_ID))
                    store.resource(accountId, spaceId, resourceId)?.let { root ->
                        queue.startIfSelected(root)?.let { scheduleOfflineTraversal(applicationContext, it.id) }
                    }
                } else {
                    scheduleOfflineMaintenance(applicationContext)
                }
                reconcileOfflineTraversals(applicationContext)
            }.fold(onSuccess = { Result.success() }, onFailure = { discoveryFailure("Background synchronization", it) })
        }

    companion object {
        const val ACCOUNT_ID = "accountId"
        const val SPACE_ID = "spaceId"
        const val RESOURCE_ID = "resourceId"
    }
}

class FolderBackupScanWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            runCatching {
                val store = store()
                val manager = TransferManager(applicationContext, store)
                val now = System.currentTimeMillis()
                var firstFailure: Throwable? = null
                store.enabledBackups().forEach { backup ->
                    runCatching { scan(backup, now, manager, store) }.onFailure {
                        it.toOpenCloudError() // Preserve cancellation before continuing another pair.
                        if (firstFailure == null) firstFailure = it
                    }
                }
                firstFailure?.let { throw it }
            }.fold(onSuccess = { Result.success() }, onFailure = { discoveryFailure("Background synchronization", it) })
        }

    private suspend fun scan(
        backup: FolderBackupEntity,
        now: Long,
        manager: TransferManager,
        store: FileBrowserStore,
    ) {
        if (!BackupExecutionPolicy.canRun(
                debug = BuildConfig.DEBUG,
                wifiOnly = backup.wifiOnly,
                chargingOnly = backup.chargingOnly,
                unmetered = isUnmetered(),
                charging = isCharging(),
            )
        ) {
            return
        }
        val inventory = BackupInventory(applicationContext, backup.id)
        val active = store.activeTransfers(backup.accountId)
        val sharedBase = if (backup.destinationKind == "SHARED_FOLDER") backup.sharedRequest() else null
        val scanStore =
            eu.opencloud.android.next.core.database.BackupScanStore(
                FileBrowserDatabase.create(applicationContext),
            )
        val sharedCollections = sharedBase?.let { SharedBackupCollections.create(applicationContext) }
        if (sharedBase == null) {
            manager.ensureBackupDestination(backup.accountId, backup.spaceId, backup.destinationPath)
        } else {
            scanStore.requireCurrent(backup)
            SharedUploadDestinationResolver.create(applicationContext).prepare(sharedBase)
        }
        val coroutine = kotlinx.coroutines.currentCoroutineContext()
        val exclusions = BackupExclusions.parse(backup.exclusionPatterns)
        val documents =
            queryBackupTree(
                applicationContext,
                Uri.parse(backup.sourceTreeUri),
                { coroutine.ensureActive() },
                exclusions,
            )
        val preparedParents = mutableSetOf(backup.destinationPath)
        val sharedParents = mutableMapOf<String, SharedFolderRequest>()
        if (sharedBase != null) sharedParents[backup.destinationPath] = sharedBase
        documents.forEach { document ->
            coroutine.ensureActive()
            if (!backup.accepts(document)) return@forEach
            val signature =
                backupSignature(document.size, document.modified, { coroutine.ensureActive() }) {
                    openUploadSource(applicationContext, document.uri)
                }
            val dateMillis = backupScanDate(applicationContext, backup, document)
            val parent = backupDestination(backup, document, dateMillis)
            if (preparedParents.add(parent)) {
                if (sharedBase == null) {
                    manager.ensureBackupDestination(backup.accountId, backup.spaceId, parent)
                } else {
                    sharedParents[parent] =
                        requireNotNull(sharedCollections).ensure(sharedBase, parent) {
                            scanStore.requireCurrent(backup)
                        }
                }
            }
            val receipt = backupReceiptKey(backup, document)
            val destination = "${parent.trimEnd('/')}/${document.name}"
            val busy =
                active.any { it.blocksBackupScan(backup.spaceId, document.uri.toString(), destination) }
            if (!busy &&
                inventory.needsUpload(receipt, signature) &&
                inventory.stable(receipt, signature, document.modified, now)
            ) {
                if (sharedBase == null) {
                    manager.enqueueUpload(
                        backup.accountId,
                        backup.spaceId,
                        parent,
                        document.uri,
                        backup,
                    )
                } else {
                    manager.enqueueSharedUpload(requireNotNull(sharedParents[parent]), document.uri, backup)
                }
                inventory.queued(receipt, signature)
            }
        }
        scanStore.complete(backup, now)
    }

    private fun isUnmetered(): Boolean {
        val manager = applicationContext.getSystemService(ConnectivityManager::class.java)
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }

    private fun isCharging(): Boolean = applicationContext.getSystemService(BatteryManager::class.java).isCharging
}

internal object BackupExecutionPolicy {
    fun canRun(
        @Suppress("UNUSED_PARAMETER") debug: Boolean,
        wifiOnly: Boolean,
        chargingOnly: Boolean,
        unmetered: Boolean,
        charging: Boolean,
    ): Boolean = (!wifiOnly || unmetered) && (!chargingOnly || charging)
}

private fun backupScanDate(
    context: Context,
    backup: FolderBackupEntity,
    document: BackupDocument,
): Long = if (backup.dateOrganization == "NONE") document.modified else backupDateEpochMillis(context, document)

private fun FolderBackupEntity.accepts(document: BackupDocument): Boolean =
    mediaType == "ALL" || document.mimeType.startsWith(mediaType.lowercase() + "/")

private fun CoroutineWorker.discoveryFailure(
    operation: String,
    throwable: Throwable,
): ListenableWorker.Result {
    if (throwable is Error) throw throwable
    if (throwable is SupersededDiscovery) {
        return if (runAttemptCount < 5) {
            ListenableWorker.Result.retry()
        } else {
            ListenableWorker.Result.failure(
                workDataOf(
                    DISCOVERY_ERROR to "Another update interrupted this refresh. Pull down to refresh again.",
                ),
            )
        }
    }
    val failure = throwable.toOpenCloudError()
    Log.e("OpenCloudSync", "$operation failed: ${failure.diagnosticCode()}")
    return if (failure == OpenCloudError.Connectivity && runAttemptCount < 5) {
        ListenableWorker.Result.retry()
    } else {
        ListenableWorker.Result.failure(workDataOf(DISCOVERY_ERROR to failure.safeMessage()))
    }
}

const val DISCOVERY_ERROR = "discoveryError"

private fun CoroutineWorker.store() = FileBrowserStore(FileBrowserDatabase.create(applicationContext))

private fun CoroutineWorker.remote(serverUrl: String) = RemoteDiscoveryClient(httpClient(serverUrl))

private fun CoroutineWorker.httpClient(serverUrl: String) =
    TlsPolicy(applicationContext).applyTo(OkHttpClient.Builder().build(), serverUrl)

internal data class FolderRefresh(
    val store: FileBrowserStore,
    val client: RemoteDiscoveryClient,
    val accountId: String,
    val space: SpaceEntity,
    val parentId: String?,
    val path: String,
    val authorization: String,
)

internal suspend fun refreshFolder(request: FolderRefresh) {
    val root = webDavRoot(request.space)
    val token = request.store.beginFolderSnapshot(request.accountId, request.space.driveId, request.parentId)
    val now = System.currentTimeMillis()
    val snapshot = request.client.folderSnapshot(root, request.path, request.authorization)
    val resources =
        snapshot.resources.map {
            ResourceEntity(
                request.accountId,
                request.space.driveId,
                it.id,
                request.parentId,
                it.path,
                it.name,
                if (it.folder) ResourceKind.FOLDER else ResourceKind.FILE,
                it.mimeType,
                it.size,
                it.eTag,
                it.modifiedAtEpochMillis,
                it.createdAtEpochMillis.takeIf { value -> value > 0 } ?: now,
                isFavorite = it.favorite,
            )
        }
    if (!request.store.replaceDiscoveredFolderSnapshot(
            request.accountId,
            request.space.driveId,
            request.parentId,
            eu.opencloud.android.next.core.database
                .FolderSnapshot(resources, snapshot.excludedVaultPaths),
            token,
        )
    ) {
        throw SupersededDiscovery()
    }
}
