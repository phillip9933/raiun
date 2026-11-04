package eu.opencloud.android.next.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.room.withTransaction
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.auth.Account
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import kotlinx.coroutines.flow.Flow

@Database(
    entities = [
        AccountEntity::class,
        SpaceEntity::class,
        ResourceEntity::class,
        TransferEntity::class,
        TransferQueueEntry::class,
        FolderBackupEntity::class,
        BackupReceipt::class,
        ShareEntity::class,
        OfflineRunEntity::class,
        OfflineNodeEntity::class,
        FavoriteCursorEntity::class,
        PendingDiscoveryEntity::class,
        FileOperationEntity::class,
        PendingPinEntity::class,
        OperationPinEntity::class,
        IncomingShareEntity::class,
        IncomingShareRefresh::class,
        SharedFolderScopeEntity::class,
        SharedFolderEntry::class,
        SharedFolderCachedPage::class,
        SharedDownloadIntent::class,
        SharedLocalFile::class,
        SharedVaultExclusion::class,
        ExcludedCacheEntity::class,
        VaultExclusion::class,
        AccountIncarnationEntity::class,
        VaultOfflineGroupEntity::class,
        VaultOfflineGroupMemberEntity::class,
        VaultOfflineGroupPublicationEntity::class,
    ],
    version = 28,
    exportSchema = true,
)
@TypeConverters(FileBrowserConverters::class)
abstract class FileBrowserDatabase : RoomDatabase() {
    internal val snapshotVersions = SnapshotVersions()
    internal val transferInventoryVersions = SnapshotVersions()
    internal val temporaryCopyVersions = SnapshotVersions()
    internal val incomingShareVersions = SnapshotVersions()
    internal val sharedFolderVersions = SnapshotVersions()

    abstract fun accountDao(): AccountDao

    abstract fun spaceDao(): SpaceDao

    abstract fun resourceDao(): ResourceDao

    abstract fun transferDao(): TransferDao

    abstract fun transferInventoryDao(): TransferInventoryDao

    abstract fun vaultOfflineGroupDao(): VaultOfflineGroupDao

    abstract fun folderBackupDao(): FolderBackupDao

    abstract fun backupReceiptDao(): BackupReceiptDao

    abstract fun shareDao(): ShareDao

    abstract fun incomingShareDao(): IncomingShareDao

    abstract fun sharedFolderCacheDao(): SharedFolderCacheDao

    abstract fun sharedDownloadDao(): SharedDownloadDao

    abstract fun sharedLocalFileDao(): SharedLocalFileDao

    abstract fun sharedVaultExclusionDao(): SharedVaultExclusionDao

    abstract fun offlineTraversalDao(): OfflineTraversalDao

    abstract fun favoriteCursorDao(): FavoriteCursorDao

    abstract fun pendingDiscoveryDao(): PendingDiscoveryDao

    abstract fun fileOperationDao(): FileOperationDao

    abstract fun pendingPinDao(): PendingPinDao

    abstract fun excludedCacheDao(): ExcludedCacheDao

    abstract fun vaultExclusionDao(): VaultExclusionDao

    companion object {
        @Volatile
        private var instance: FileBrowserDatabase? = null

        @Suppress("SpreadOperator") // Copies migration references once when opening the database.
        fun create(context: Context): FileBrowserDatabase =
            instance ?: synchronized(this) {
                instance ?: Room
                    .databaseBuilder(
                        context.applicationContext,
                        FileBrowserDatabase::class.java,
                        "opencloud-file-browser.db",
                    ).addMigrations(*MIGRATIONS)
                    .build()
                    .also { instance = it }
            }

        private val MIGRATION_1_2 =
            object : Migration(1, 2) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) = Unit
            }

        private val MIGRATION_2_3 =
            object : Migration(2, 3) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS `accounts` (`id` TEXT NOT NULL, `serverUrl` TEXT NOT NULL, " +
                            "`userId` TEXT NOT NULL, `displayName` TEXT NOT NULL, " +
                            "`authenticationType` TEXT NOT NULL, " +
                            "`tusSupported` INTEGER NOT NULL, `isActive` INTEGER NOT NULL, PRIMARY KEY(`id`))",
                    )
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS `transfers` (`id` TEXT NOT NULL, `accountId` TEXT NOT NULL, " +
                            "`spaceId` TEXT NOT NULL, `resourceId` TEXT, " +
                            "`direction` TEXT NOT NULL, `sourceUri` TEXT, " +
                            "`destinationPath` TEXT NOT NULL, `displayName` TEXT NOT NULL, `mimeType` TEXT, " +
                            "`bytesTotal` INTEGER NOT NULL, `bytesTransferred` INTEGER NOT NULL, " +
                            "`state` TEXT NOT NULL, `error` TEXT, `workId` TEXT, " +
                            "`overwrite` INTEGER NOT NULL, `offlinePin` INTEGER NOT NULL, " +
                            "`tusUrl` TEXT, `tusOffset` INTEGER NOT NULL, `attemptCount` INTEGER NOT NULL, " +
                            "`createdAtEpochMillis` INTEGER NOT NULL, `updatedAtEpochMillis` INTEGER NOT NULL, " +
                            "PRIMARY KEY(`id`))",
                    )
                    db.execSQL(
                        "CREATE INDEX IF NOT EXISTS `index_transfers_accountId_state` " +
                            "ON `transfers` (`accountId`, `state`)",
                    )
                    db.execSQL(
                        "CREATE INDEX IF NOT EXISTS `index_transfers_accountId_spaceId_resourceId_direction` " +
                            "ON `transfers` (`accountId`, `spaceId`, `resourceId`, `direction`)",
                    )
                }
            }

        private val MIGRATION_3_4 =
            object : Migration(3, 4) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `oidcIssuer` TEXT")
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `oidcTokenEndpoint` TEXT")
                    db.execSQL(
                        "ALTER TABLE `transfers` ADD COLUMN `deleteSourceAfterSuccess` INTEGER NOT NULL DEFAULT 0",
                    )
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS `folder_backups` (`id` TEXT NOT NULL, " +
                            "`accountId` TEXT NOT NULL, `spaceId` TEXT NOT NULL, `sourceTreeUri` TEXT NOT NULL, " +
                            "`destinationPath` TEXT NOT NULL, " +
                            "`mediaType` TEXT NOT NULL, `wifiOnly` INTEGER NOT NULL, " +
                            "`chargingOnly` INTEGER NOT NULL, " +
                            "`deleteAfterUpload` INTEGER NOT NULL, `enabled` INTEGER NOT NULL, " +
                            "`lastSafeScanEpochMillis` INTEGER NOT NULL, PRIMARY KEY(`id`))",
                    )
                    db.execSQL(
                        "CREATE UNIQUE INDEX IF NOT EXISTS `index_folder_backups_accountId_sourceTreeUri_mediaType` " +
                            "ON `folder_backups` (`accountId`, `sourceTreeUri`, `mediaType`)",
                    )
                }
            }

        private val MIGRATION_4_5 =
            object : Migration(4, 5) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL(
                        "ALTER TABLE `folder_backups` ADD COLUMN `sourceDisplayName` TEXT NOT NULL DEFAULT ''",
                    )
                }
            }

        private val MIGRATION_5_6 =
            object : Migration(5, 6) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `remoteSearchUrl` TEXT")
                }
            }

        private val MIGRATION_6_7 =
            object : Migration(6, 7) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `trashSupported` INTEGER NOT NULL DEFAULT 0")
                }
            }

        private val MIGRATION_7_8 =
            object : Migration(7, 8) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `sharingEnabled` INTEGER NOT NULL DEFAULT 0")
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `publicSharingEnabled` INTEGER NOT NULL DEFAULT 0")
                    db.execSQL(
                        "ALTER TABLE `accounts` ADD COLUMN `publicLinkPasswordSupported` INTEGER NOT NULL DEFAULT 0",
                    )
                    db.execSQL(
                        "ALTER TABLE `accounts` ADD COLUMN `publicLinkPasswordEnforced` INTEGER NOT NULL DEFAULT 0",
                    )
                    db.execSQL(
                        "ALTER TABLE `accounts` ADD COLUMN `publicLinkExpirationSupported` INTEGER NOT NULL DEFAULT 0",
                    )
                    db.execSQL(
                        "ALTER TABLE `accounts` ADD COLUMN `publicLinkExpirationEnforced` INTEGER NOT NULL DEFAULT 0",
                    )
                    db.execSQL("ALTER TABLE `accounts` ADD COLUMN `publicLinkExpirationDays` INTEGER")
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS `shares` (`accountId` TEXT NOT NULL, `remoteId` TEXT NOT NULL, `resourceId` TEXT, `path` TEXT NOT NULL, `shareType` INTEGER NOT NULL, `shareWith` TEXT, `displayName` TEXT, `additionalInfo` TEXT, `permissions` INTEGER NOT NULL, `sharedAtEpochSeconds` INTEGER NOT NULL, `expiresAtEpochMillis` INTEGER, `label` TEXT, `isFolder` INTEGER NOT NULL, `sharedWithMe` INTEGER NOT NULL, PRIMARY KEY(`accountId`, `remoteId`))",
                    )
                    db.execSQL(
                        "CREATE INDEX IF NOT EXISTS `index_shares_accountId_sharedWithMe` ON `shares` (`accountId`, `sharedWithMe`)",
                    )
                    db.execSQL(
                        "CREATE INDEX IF NOT EXISTS `index_shares_accountId_path` ON `shares` (`accountId`, `path`)",
                    )
                }
            }

        val MIGRATION_9_10 =
            object : Migration(9, 10) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE transfers ADD COLUMN errorCode TEXT")
                    db.execSQL("ALTER TABLE transfers ADD COLUMN notBeforeEpochMillis INTEGER NOT NULL DEFAULT 0")
                    db.execSQL(
                        "UPDATE transfers SET error = 'The operation could not be completed.' WHERE error IS NOT NULL",
                    )
                }
            }

        private val MIGRATION_8_9 =
            object : Migration(8, 9) {
                override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `driveAlias` TEXT")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `webUrl` TEXT")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `ownerId` TEXT")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `lastModifiedDateTime` TEXT")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `quotaUsedBytes` INTEGER")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `quotaRemainingBytes` INTEGER")
                    db.execSQL("ALTER TABLE `spaces` ADD COLUMN `quotaState` TEXT")
                }
            }

        val MIGRATIONS: Array<Migration> =
            arrayOf(
                MIGRATION_1_2,
                MIGRATION_2_3,
                MIGRATION_3_4,
                MIGRATION_4_5,
                MIGRATION_5_6,
                MIGRATION_6_7,
                MIGRATION_7_8,
                MIGRATION_8_9,
                MIGRATION_9_10,
                MIGRATION_10_11,
                MIGRATION_11_12,
                MIGRATION_12_13,
                MIGRATION_13_14,
                MIGRATION_14_15,
                MIGRATION_15_16,
                MIGRATION_16_17,
                MIGRATION_17_18,
                MIGRATION_18_19,
                MIGRATION_19_20,
                MIGRATION_20_21,
                MIGRATION_21_22,
                MIGRATION_22_23,
                MIGRATION_23_24,
                MIGRATION_24_25,
                MIGRATION_25_26,
                MIGRATION_26_27,
                MIGRATION_27_28,
            )
    }
}

class FileBrowserStore(
    internal val database: FileBrowserDatabase,
) {
    suspend fun favoriteCursor(accountId: String): FavoriteCursorEntity? = database.favoriteCursorDao().find(accountId)

    suspend fun advanceFavoriteCursor(
        accountId: String,
        spaceId: String,
        resourceId: String,
        expected: FavoriteCursorEntity?,
    ): FavoriteCursorEntity? =
        database.withTransaction {
            if (database.accountDao().findById(accountId)?.isActive != true ||
                database.favoriteCursorDao().find(accountId) != expected
            ) {
                return@withTransaction null
            }
            val next =
                FavoriteCursorEntity(
                    accountId,
                    spaceId,
                    resourceId,
                    java.util.UUID
                        .randomUUID()
                        .toString(),
                )
            database.favoriteCursorDao().save(next)
            next
        }

    suspend fun beginFolderSnapshot(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): SnapshotToken =
        database.withTransaction {
            database.snapshotVersions.beginFolder(accountId, FolderSnapshotScope(spaceId, parentId))
        }

    suspend fun beginSnapshot(accountId: String): SnapshotToken =
        database.withTransaction {
            database.snapshotVersions.begin(accountId)
        }

    private val spaces = database.spaceDao()
    private val resources = database.resourceDao()
    private val transfers = database.transferDao()
    private val backups = database.folderBackupDao()
    private val shares = database.shareDao()

    suspend fun saveAccount(
        account: Account,
        capabilities: ServerCapabilities,
        oidcConfiguration: eu.opencloud.android.next.core.model.auth.OidcConfiguration? = null,
    ) = database.upsertOwnedAccount(
        AccountEntity(
            id = account.id,
            serverUrl = account.serverUrl,
            userId = account.userId,
            displayName = account.displayName,
            authenticationType = account.authenticationType.name,
            tusSupported = capabilities.tusSupported,
            oidcIssuer = oidcConfiguration?.issuer,
            oidcTokenEndpoint = oidcConfiguration?.tokenEndpoint,
            remoteSearchUrl = capabilities.remoteSearchUrl,
            trashSupported = capabilities.trashSupported,
            sharingEnabled = capabilities.sharingEnabled,
            publicSharingEnabled = capabilities.publicSharingEnabled,
            publicLinkPasswordSupported = capabilities.publicLinkPasswordSupported,
            publicLinkPasswordEnforced = capabilities.publicLinkPasswordEnforced,
            publicLinkExpirationSupported = capabilities.publicLinkExpirationSupported,
            publicLinkExpirationEnforced = capabilities.publicLinkExpirationEnforced,
            publicLinkExpirationDays = capabilities.publicLinkExpirationDays,
        ),
    )

    fun observeAccounts(): Flow<List<AccountEntity>> = database.accountDao().observeActive()

    suspend fun publishCapabilities(
        accountId: String,
        serverUrl: String,
        capabilities: ServerCapabilities,
    ): Boolean =
        database.withTransaction {
            val current = database.accountDao().findById(accountId) ?: return@withTransaction false
            if (current.serverUrl != serverUrl) return@withTransaction false
            database.accountDao().upsert(
                current.copy(
                    tusSupported = capabilities.tusSupported,
                    remoteSearchUrl = capabilities.remoteSearchUrl,
                    trashSupported = capabilities.trashSupported,
                    sharingEnabled = capabilities.sharingEnabled,
                    publicSharingEnabled = capabilities.publicSharingEnabled,
                    publicLinkPasswordSupported = capabilities.publicLinkPasswordSupported,
                    publicLinkPasswordEnforced = capabilities.publicLinkPasswordEnforced,
                    publicLinkExpirationSupported = capabilities.publicLinkExpirationSupported,
                    publicLinkExpirationEnforced = capabilities.publicLinkExpirationEnforced,
                    publicLinkExpirationDays = capabilities.publicLinkExpirationDays,
                ),
            )
            true
        }

    fun observeFavorites(accountId: String): Flow<List<ResourceEntity>> = resources.observeFavorites(accountId)

    fun observeOffline(accountId: String): Flow<List<ResourceEntity>> = resources.observeOffline(accountId)

    fun observeRecent(
        accountId: String,
        ids: List<String>,
    ): Flow<List<ResourceEntity>> = resources.observeRecent(accountId, ids)

    fun observeSpaces(accountId: String): Flow<List<SpaceEntity>> = spaces.observeSpaces(accountId)

    fun observeChildren(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): Flow<List<ResourceEntity>> = resources.observeChildren(accountId, spaceId, parentId)

    fun searchResources(
        accountId: String,
        query: String,
    ): Flow<List<ResourceEntity>> = resources.search(accountId, query.toLikePattern())

    fun transferInventory(): TransferInventory = TransferInventory(database)

    fun observeTransfers(accountId: String): Flow<List<TransferEntity>> = transfers.observeForAccount(accountId)

    fun observeTransfer(
        accountId: String,
        id: String,
    ): Flow<TransferEntity?> = transfers.observeById(accountId, id)

    fun observeBackups(accountId: String): Flow<List<FolderBackupEntity>> = backups.observeForAccount(accountId)

    fun observeShares(accountId: String): Flow<List<ShareEntity>> = shares.observeForAccount(accountId)

    suspend fun account(accountId: String): AccountEntity? = database.accountDao().findById(accountId)

    suspend fun space(
        accountId: String,
        spaceId: String,
    ): SpaceEntity? = spaces.findById(accountId, spaceId)

    suspend fun resource(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): ResourceEntity? = resources.findById(accountId, spaceId, resourceId)

    suspend fun createTransfer(transfer: TransferEntity) = transfers.insert(transfer)

    suspend fun enqueueTransfer(transfer: TransferEntity): TransferEntity =
        database.withTransaction {
            require(
                !database.vaultExclusionDao().denies(transfer.accountId, transfer.spaceId, transfer.destinationPath),
            ) {
                "Encrypted vault locations are unavailable."
            }
            require(transfer.locationKind == "SPACE")
            requireNotNull(database.accountDao().findById(transfer.accountId)) { "The account is unavailable." }
            val space = requireNotNull(spaces.findById(transfer.accountId, transfer.spaceId))
            require(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
            val existing =
                if (transfer.direction == TransferDirection.DOWNLOAD.name) {
                    val resourceId = requireNotNull(transfer.resourceId)
                    val resource = requireNotNull(resources.findById(transfer.accountId, transfer.spaceId, resourceId))
                    require(
                        resource.kind == ResourceKind.FILE &&
                            resource.path == transfer.destinationPath &&
                            resource.sizeBytes == transfer.bytesTotal,
                    ) { "The file changed. Refresh before downloading." }
                    if (transfer.offlinePin) {
                        resources.setOfflinePinned(
                            transfer.accountId,
                            transfer.spaceId,
                            resourceId,
                            true,
                        )
                    }
                    transfers.findActiveDownload(transfer.accountId, transfer.spaceId, resourceId)
                } else {
                    require(transfer.direction == TransferDirection.UPLOAD.name)
                    transfers.findActiveUpload(
                        transfer.accountId,
                        transfer.spaceId,
                        requireNotNull(transfer.sourceUri),
                        transfer.destinationPath,
                    )
                }
            existing ?: transfer.also { transfers.insert(it) }
        }

    suspend fun updateTransfer(transfer: TransferEntity) = transfers.update(transfer)

    /** Admission for a committed ciphertext payload; ordinary vault exclusions remain intact. */
    suspend fun enqueueCiphertextUpload(transfer: TransferEntity): TransferEntity =
        database.enqueuePreparedCiphertextUpload(transfer)

    suspend fun retryCiphertextUpload(
        expected: TransferEntity,
        replacement: TransferEntity,
        scope: TransferBulkScope? = null,
    ): TransferEntity? = database.retryPreparedCiphertextTransfer(expected, replacement, scope)

    suspend fun retryTransfer(
        expected: TransferEntity,
        replacement: TransferEntity,
        scope: TransferBulkScope? = null,
    ): TransferEntity? = database.retryAllowedTransfer(expected, replacement, scope)

    fun observeAwaitingCiphertextDownloads(
        account: String,
        scope: String,
    ): Flow<String?> = transfers.observeAwaitingCiphertextDownloads(account, scope)

    suspend fun awaitingCiphertextDownloadsPage(
        account: String,
        scope: String,
        afterId: String,
        limit: Int,
    ): List<TransferEntity> = transfers.awaitingCiphertextDownloadsPage(account, scope, afterId, limit)

    suspend fun enqueueCiphertextDownload(transfer: TransferEntity): TransferEntity =
        database.enqueuePreparedCiphertextDownload(transfer)

    suspend fun completeAwaitingCiphertextDownload(
        expected: TransferEntity,
        replacement: TransferEntity,
    ): Boolean = database.completePendingCiphertextDownload(expected, replacement)

    suspend fun claimTransfer(
        id: String,
        workerId: String,
        now: Long,
    ) = database.claimAllowedTransfer(id, workerId, now)

    suspend fun updateActiveTransfer(transfer: TransferEntity) = transfers.updateActive(transfer)

    suspend fun updateTransferProgress(
        transfer: TransferEntity,
        bytes: Long,
        now: Long,
    ): Boolean = transfers.updateProgress(transfer.id, transfer.workId, bytes, now) == 1

    suspend fun recordScheduledWork(
        transfer: TransferEntity,
        workId: String,
        now: Long,
    ) = transfers.schedule(transfer, workId, now)

    suspend fun cancelTransfer(id: String) = database.cancelOwnedTransfer(id)

    suspend fun cancelUploadConflicts(
        accountId: String,
        now: Long,
    ): Int = transfers.cancelUploadConflicts(accountId, now)

    suspend fun activeAccounts(): List<AccountEntity> = database.accountDao().findActive()

    suspend fun setFavorite(
        resource: ResourceEntity,
        favorite: Boolean,
    ) = database.withTransaction {
        database.snapshotVersions.begin(resource.accountId)
        resources.setFavorite(resource.accountId, resource.spaceId, resource.remoteId, favorite)
    }

    /** Reconciles cached identities only; it does not invent parent/location metadata for unseen items. */
    suspend fun replaceFavoriteSnapshot(
        accountId: String,
        snapshot: Map<String, Set<String>>,
        token: SnapshotToken,
    ): Boolean =
        database.withTransaction {
            if (!database.snapshotVersions.accept(accountId, token)) return@withTransaction false
            snapshot.forEach { (spaceId, ids) ->
                resources.clearFavorites(accountId, spaceId)
                ids.forEach { resources.setFavorite(accountId, spaceId, it, true) }
            }
            true
        }

    suspend fun removeAccount(accountId: String) {
        database.withTransaction {
            database.invalidateAccountScopes(accountId)
            database.vaultOfflineGroupDao().deleteOwner(accountId)
            database.offlineTraversalDao().deleteAccount(accountId)
            database.favoriteCursorDao().delete(accountId)
            database.pendingDiscoveryDao().deleteAccount(accountId)
            database.pendingPinDao().deleteOperationPins(accountId)
            database.fileOperationDao().deleteAccount(accountId)
            database.pendingPinDao().deleteAccount(accountId)
            database.backupReceiptDao().deleteAccount(accountId)
            database.vaultExclusionDao().deleteAccount(accountId)
            backups.deleteForAccount(accountId)
            transfers.deleteAllForAccount(accountId)
            resources.deleteForAccount(accountId)
            shares.deleteForAccount(accountId)
            spaces.deleteForAccount(accountId)
            database.accountDao().delete(accountId)
        }
    }

    suspend fun spaces(accountId: String): List<SpaceEntity> = spaces.findSpaces(accountId)

    suspend fun replaceShares(
        accountId: String,
        values: List<ShareEntity>,
    ) {
        database.withTransaction {
            shares.deleteForAccount(accountId)
            shares.upsertAll(values)
        }
    }

    /** Publish one server-confirmed mutation without depending on a subsequent account-wide refresh. */
    suspend fun saveConfirmedShare(value: ShareEntity): Boolean =
        database.withTransaction {
            if (database.accountDao().findById(value.accountId)?.isActive != true) return@withTransaction false
            shares.upsertAll(listOf(value))
            true
        }

    suspend fun deleteShare(
        accountId: String,
        shareId: String,
    ) = shares.delete(accountId, shareId)

    suspend fun children(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): List<ResourceEntity> = resources.findChildren(accountId, spaceId, parentId)

    suspend fun childCount(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): Int = resources.countChildren(accountId, spaceId, parentId)

    suspend fun childrenPage(
        accountId: String,
        spaceId: String,
        parentId: String?,
        offset: Int,
    ): List<ResourceEntity> = resources.childrenPage(accountId, spaceId, parentId, offset.coerceAtLeast(0))

    suspend fun child(
        accountId: String,
        spaceId: String,
        parentId: String?,
        name: String,
    ): ResourceEntity? = resources.findChild(accountId, spaceId, parentId, name)

    suspend fun resources(
        accountId: String,
        spaceId: String,
    ): List<ResourceEntity> = resources.findBySpace(accountId, spaceId)

    suspend fun providerSearch(
        accountId: String,
        query: String,
    ): List<ResourceEntity> = resources.providerSearch(accountId, query)

    suspend fun transfer(id: String): TransferEntity? = transfers.findById(id)

    suspend fun referencesCache(path: String): Boolean = resources.referencesCache(path)

    suspend fun pendingDiscoveries(after: String = ""): List<PendingDiscoveryEntity> =
        database.pendingDiscoveryDao().page(after)

    suspend fun pendingDiscovery(revision: String): PendingDiscoveryEntity? =
        database.pendingDiscoveryDao().find(revision)

    suspend fun acknowledgeDiscovery(revision: String) = database.pendingDiscoveryDao().acknowledge(revision)

    suspend fun queueFolderRefresh(
        accountId: String,
        spaceId: String,
        folderId: String?,
    ) = database.withTransaction {
        val space = spaces.findById(accountId, spaceId)
        val available = space != null && !space.isDisabled && !space.isDeleted
        if (database.accountDao().findById(accountId) != null && available) {
            database.snapshotVersions.begin(accountId)
            database.pendingDiscoveryDao().save(
                PendingDiscoveryEntity(
                    accountId,
                    spaceId,
                    folderId.orEmpty(),
                    java.util.UUID
                        .randomUUID()
                        .toString(),
                ),
            )
        }
    }

    suspend fun resourceAtPath(
        accountId: String,
        spaceId: String,
        path: String,
    ): ResourceEntity? = resources.findByPath(accountId, spaceId, path)

    suspend fun pendingTransfers(): List<TransferEntity> = transfers.findPending()

    suspend fun pendingTransferPage(afterId: String): List<TransferEntity> = transfers.findPendingPage(afterId, 256)

    suspend fun blockedDownload(resource: ResourceEntity): TransferEntity? =
        transfers.findBlockedDownload(
            resource.accountId,
            resource.spaceId,
            resource.remoteId,
            resource.path,
            resource.sizeBytes,
        )

    suspend fun hasActiveBackupUpload(
        accountId: String,
        spaceId: String,
        sourceUri: String,
        destinationPath: String,
    ): Boolean = transfers.hasActiveBackupUpload(accountId, spaceId, sourceUri, destinationPath)

    suspend fun activeTransfers(accountId: String): List<TransferEntity> = transfers.findForAccount(accountId)

    suspend fun activeDownload(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): TransferEntity? = transfers.findActiveDownload(accountId, spaceId, resourceId)

    suspend fun activeUpload(
        accountId: String,
        spaceId: String,
        sourceUri: String,
        destinationPath: String,
    ): TransferEntity? = transfers.findActiveUpload(accountId, spaceId, sourceUri, destinationPath)

    suspend fun updateLocalCopy(
        accountId: String,
        spaceId: String,
        resourceId: String,
        localPath: String,
    ) = resources.updateLocalCopy(accountId, spaceId, resourceId, true, localPath)

    fun observeOfflinePins(accountId: String): Flow<List<ResourceEntity>> = resources.observeOfflinePins(accountId)

    suspend fun expireTemporaryCopy(
        expected: ResourceEntity,
        deleteIfOld: () -> Boolean,
    ): Boolean =
        database.withTransaction {
            val current = resources.findById(expected.accountId, expected.spaceId, expected.remoteId)
            if (current != expected || current.offlinePinned) return@withTransaction false
            if (database.offlineTraversalDao().coveringRoot(
                    current.accountId,
                    current.spaceId,
                    current.remoteId,
                    current.path,
                ) !=
                null ||
                transfers.findActiveDownload(current.accountId, current.spaceId, current.remoteId) != null
            ) {
                return@withTransaction false
            }
            if (!deleteIfOld()) return@withTransaction false
            resources.updateLocalCopy(current.accountId, current.spaceId, current.remoteId, false, null)
            true
        }

    suspend fun invalidateFileContent(resource: ResourceEntity) = invalidateFileContent(database, resource)

    suspend fun clearLocalCopy(resource: ResourceEntity) =
        database.withTransaction {
            setOfflinePinned(resource, false)
            resources.updateLocalCopy(resource.accountId, resource.spaceId, resource.remoteId, false, null)
        }

    suspend fun clearMatchingLocalCopy(expected: ResourceEntity): Boolean =
        database.withTransaction {
            val current = resources.findById(expected.accountId, expected.spaceId, expected.remoteId)
            if (current?.localPath != expected.localPath ||
                current?.eTag != expected.eTag ||
                current?.sizeBytes != expected.sizeBytes
            ) {
                false
            } else {
                clearLocalCopy(expected)
                true
            }
        }

    suspend fun publishDownload(
        transfer: TransferEntity,
        expected: ResourceEntity,
        localPath: String,
    ): Boolean =
        database.withTransaction {
            val active = transfers.findById(transfer.id)
            val space = spaces.findById(expected.accountId, expected.spaceId)
            val spaceAvailable = space != null && !space.isDisabled && !space.isDeleted
            val available = database.accountDao().findById(expected.accountId) != null && spaceAvailable
            val current = resources.findById(expected.accountId, expected.spaceId, expected.remoteId)
            val unchanged =
                current?.path == expected.path &&
                    current?.eTag == expected.eTag &&
                    current?.sizeBytes == expected.sizeBytes
            val owned = active?.state == "RUNNING" && active.workId == transfer.workId
            if (!owned || !unchanged || !available) {
                return@withTransaction false
            }
            resources.updateLocalCopy(expected.accountId, expected.spaceId, expected.remoteId, true, localPath)
            true
        }

    suspend fun completeUpload(transfer: TransferEntity): Boolean =
        database.withTransaction {
            val active = transfers.findById(transfer.id)
            val space = spaces.findById(transfer.accountId, transfer.spaceId)
            val owned = active?.state == "RUNNING" && active.workId == transfer.workId
            val available = space != null && !space.isDisabled && !space.isDeleted
            if (!owned || !available || database.accountDao().findById(transfer.accountId) == null) {
                return@withTransaction false
            }
            database.snapshotVersions.begin(transfer.accountId)
            // Discovery owns resource identity and metadata. Only invalidate previously cached bytes here.
            resources.invalidatePathCache(transfer.accountId, transfer.spaceId, transfer.destinationPath)
            val parentPath = transfer.destinationPath.substringBeforeLast('/', "")
            val parent = resources.findByPath(transfer.accountId, transfer.spaceId, parentPath)
            queueFolderRefresh(transfer.accountId, transfer.spaceId, parent?.remoteId)
            true
        }

    suspend fun clearTransferHistory(accountId: String) = database.clearRemovalAwareTransferHistory(accountId)

    suspend fun clearTransfers(accountId: String) = transfers.deleteAllForAccount(accountId)

    suspend fun enabledBackups(): List<FolderBackupEntity> = backups.findEnabled()

    suspend fun backup(id: String): FolderBackupEntity? = backups.findById(id)

    suspend fun saveBackup(configuration: FolderBackupEntity) = BackupScanStore(database).save(configuration)

    suspend fun deleteBackup(id: String) =
        database.withTransaction {
            database.backupReceiptDao().deletePair(id)
            backups.delete(id)
        }

    suspend fun setOfflinePinned(
        resource: ResourceEntity,
        pinned: Boolean,
    ) = VaultMutationGuard(database).setOfflinePinned(resource, pinned)

    suspend fun requireCurrentMutableResource(
        resource: ResourceEntity,
        includeDescendants: Boolean = true,
    ): ResourceEntity = VaultMutationGuard(database).requireCurrentResource(resource, includeDescendants)

    suspend fun requireAllowedFolderDestination(
        accountId: String,
        spaceId: String,
        parentId: String?,
        expectedParentPath: String?,
        destinationPath: String,
    ) = VaultMutationGuard(database).requireFolderDestination(
        accountId,
        spaceId,
        parentId,
        expectedParentPath,
        destinationPath,
    )

    suspend fun requireAllowedVaultPath(
        accountId: String,
        spaceId: String,
        path: String,
        includeChildren: Boolean = false,
    ) = VaultMutationGuard(database).requireAllowedPath(accountId, spaceId, path, includeChildren)

    suspend fun offlinePinnedResources(): List<ResourceEntity> = resources.findOfflinePinned()

    suspend fun replaceRemoteSpaces(
        accountId: String,
        snapshot: List<SpaceEntity>,
        token: SnapshotToken? = null,
        excludedVaultIds: Set<String> = emptySet(),
        publicationGuard: () -> Unit = {},
    ): Boolean =
        RemoteSnapshotStore(database).replaceRemoteSpaces(
            accountId,
            snapshot,
            token,
            excludedVaultIds,
            publicationGuard,
        )

    suspend fun replaceFolderSnapshot(
        accountId: String,
        spaceId: String,
        parentId: String?,
        snapshot: List<ResourceEntity>,
        token: SnapshotToken? = null,
    ): Boolean = replaceDiscoveredFolderSnapshot(accountId, spaceId, parentId, FolderSnapshot(snapshot), token)

    suspend fun replaceDiscoveredFolderSnapshot(
        accountId: String,
        spaceId: String,
        parentId: String?,
        discovered: FolderSnapshot,
        token: SnapshotToken? = null,
    ): Boolean =
        RemoteSnapshotStore(database).replaceDiscoveredFolderSnapshot(
            accountId,
            spaceId,
            parentId,
            discovered,
            token,
        )

    suspend fun replaceStagedFolderSnapshot(
        accountId: String,
        scope: FolderSnapshotScope,
        source: FolderSnapshotReader,
        token: SnapshotToken? = null,
        publicationGuard: () -> Unit = {},
    ): Boolean =
        RemoteSnapshotStore(database).replaceStagedFolderSnapshot(
            accountId,
            scope,
            source,
            token,
            publicationGuard,
        )

    @Suppress("UNUSED_PARAMETER", "UnusedParameter") // Unsafe local-only operation is contained pending server support.
    suspend fun createSpace(
        accountId: String,
        name: String,
    ) {
        error("This action is not available yet.")
    }

    @Transaction
    @Suppress("UNUSED_PARAMETER", "UnusedParameter") // Unsafe local-only operation is contained pending server support.
    suspend fun rename(
        accountId: String,
        spaceId: String,
        resourceId: String,
        name: String,
    ) {
        error("This action is not available yet.")
    }

    @Transaction
    @Suppress("UNUSED_PARAMETER", "UnusedParameter") // Unsafe local-only operation is contained pending server support.
    suspend fun move(
        accountId: String,
        spaceId: String,
        resourceId: String,
        targetParentId: String?,
    ) {
        error("This action is not available yet.")
    }

    @Transaction
    @Suppress("UNUSED_PARAMETER", "UnusedParameter") // Unsafe local-only operation is contained pending server support.
    suspend fun copy(
        accountId: String,
        spaceId: String,
        resourceId: String,
        targetParentId: String?,
    ) {
        error("This action is not available yet.")
    }

    @Transaction
    suspend fun delete(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ) = database.withTransaction {
        database.snapshotVersions.begin(accountId)
        resources.findById(accountId, spaceId, resourceId)?.let { resource ->
            if (resource.kind == ResourceKind.FOLDER) {
                resources.deleteDescendants(accountId, spaceId, "${resource.path.trimEnd('/')}/")
            }
            resources.delete(resource)
        }
    }
}

internal fun String.toLikePattern(): String = "%${replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")}%"
