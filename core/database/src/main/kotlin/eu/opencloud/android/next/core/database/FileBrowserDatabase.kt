package eu.opencloud.android.next.core.database

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import androidx.room.Update
import androidx.room.Upsert
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
    ],
    version = 24,
    exportSchema = true,
)
@TypeConverters(FileBrowserConverters::class)
abstract class FileBrowserDatabase : RoomDatabase() {
    internal val snapshotVersions = SnapshotVersions()
    internal val incomingShareVersions = SnapshotVersions()
    internal val sharedFolderVersions = SnapshotVersions()

    abstract fun accountDao(): AccountDao

    abstract fun spaceDao(): SpaceDao

    abstract fun resourceDao(): ResourceDao

    abstract fun transferDao(): TransferDao

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
            )
    }
}

class FileBrowserConverters {
    @TypeConverter
    fun resourceKindToString(value: ResourceKind): String = value.name

    @TypeConverter
    fun stringToResourceKind(value: String): ResourceKind = ResourceKind.valueOf(value)
}

@Entity(tableName = "accounts")
data class AccountEntity(
    @androidx.room.PrimaryKey val id: String,
    val serverUrl: String,
    val userId: String,
    val displayName: String,
    val authenticationType: String,
    val tusSupported: Boolean,
    val isActive: Boolean = true,
    val oidcIssuer: String? = null,
    val oidcTokenEndpoint: String? = null,
    val remoteSearchUrl: String? = null,
    val trashSupported: Boolean = false,
    val sharingEnabled: Boolean = false,
    val publicSharingEnabled: Boolean = false,
    val publicLinkPasswordSupported: Boolean = false,
    val publicLinkPasswordEnforced: Boolean = false,
    val publicLinkExpirationSupported: Boolean = false,
    val publicLinkExpirationEnforced: Boolean = false,
    val publicLinkExpirationDays: Int? = null,
)

@Entity(
    tableName = "spaces",
    primaryKeys = ["accountId", "driveId"],
    indices = [Index(value = ["accountId", "name"])],
)
data class SpaceEntity(
    val accountId: String,
    val driveId: String,
    val name: String,
    val type: String,
    val description: String?,
    val ownerName: String?,
    val rootId: String,
    val rootWebDavUrl: String?,
    val rootETag: String?,
    val quotaBytes: Long?,
    val isDisabled: Boolean = false,
    val isDeleted: Boolean = false,
    val driveAlias: String? = null,
    val webUrl: String? = null,
    val ownerId: String? = null,
    val lastModifiedDateTime: String? = null,
    val quotaUsedBytes: Long? = null,
    val quotaRemainingBytes: Long? = null,
    val quotaState: String? = null,
)

@Entity(
    tableName = "resources",
    primaryKeys = ["accountId", "spaceId", "remoteId"],
    indices = [
        Index(value = ["accountId", "spaceId", "parentId", "name"], unique = true),
        Index(value = ["accountId", "spaceId", "parentId"]),
        Index(value = ["accountId", "spaceId", "parentId", "remoteId"]),
        Index(value = ["offlinePinned", "kind", "accountId", "spaceId"]),
    ],
)
data class ResourceEntity(
    val accountId: String,
    val spaceId: String,
    val remoteId: String,
    val parentId: String?,
    val path: String,
    val name: String,
    val kind: ResourceKind,
    val mimeType: String?,
    val sizeBytes: Long,
    val eTag: String?,
    val modifiedAtEpochMillis: Long,
    val createdAtEpochMillis: Long,
    val isFavorite: Boolean = false,
    val hasLocalCopy: Boolean = false,
    val localPath: String? = null,
    val offlinePinned: Boolean = false,
)

@Entity(
    tableName = "transfers",
    indices = [
        Index(value = ["accountId", "state"]),
        Index(value = ["accountId", "spaceId", "resourceId", "direction"]),
    ],
)
data class TransferEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val spaceId: String,
    val resourceId: String?,
    val direction: String,
    val sourceUri: String?,
    val destinationPath: String,
    val displayName: String,
    val mimeType: String?,
    val bytesTotal: Long,
    val bytesTransferred: Long = 0,
    val state: String = TransferState.QUEUED.name,
    val error: String? = null,
    val workId: String? = null,
    val overwrite: Boolean = false,
    val offlinePin: Boolean = false,
    val deleteSourceAfterSuccess: Boolean = false,
    val tusUrl: String? = null,
    val tusOffset: Long = 0,
    val attemptCount: Int = 0,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
    val errorCode: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "0") val notBeforeEpochMillis: Long = 0,
    @androidx.room.ColumnInfo(defaultValue = "0") val verificationPending: Boolean = false,
    val expectedETag: String? = null,
    val verifiedETag: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "'SPACE'") val locationKind: String = "SPACE",
)

enum class TransferDirection { UPLOAD, DOWNLOAD }

enum class TransferState { QUEUED, RUNNING, RETRY, CONFLICT, SUCCEEDED, FAILED, CANCELLED }

@Entity(
    tableName = "folder_backups",
    indices = [Index(value = ["accountId", "sourceTreeUri", "mediaType"], unique = true)],
)
data class FolderBackupEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val spaceId: String,
    val sourceTreeUri: String,
    val sourceDisplayName: String = "",
    val destinationPath: String,
    val mediaType: String,
    val wifiOnly: Boolean,
    val chargingOnly: Boolean,
    val deleteAfterUpload: Boolean,
    val enabled: Boolean = true,
    val lastSafeScanEpochMillis: Long = 0,
    @androidx.room.ColumnInfo(defaultValue = "'NONE'") val dateOrganization: String = "NONE",
    @androidx.room.ColumnInfo(defaultValue = "'SPACE'") val destinationKind: String = "SPACE",
    val sharedShareId: String? = null,
    val sharedFolderId: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "0") val destinationRevision: Long = 0,
)

@Entity(
    tableName = "shares",
    primaryKeys = ["accountId", "remoteId"],
    indices = [Index(value = ["accountId", "sharedWithMe"]), Index(value = ["accountId", "path"])],
)
data class ShareEntity(
    val accountId: String,
    val remoteId: String,
    val resourceId: String?,
    val path: String,
    val shareType: Int,
    val shareWith: String?,
    val displayName: String?,
    val additionalInfo: String?,
    val permissions: Int,
    val sharedAtEpochSeconds: Long,
    val expiresAtEpochMillis: Long?,
    val label: String?,
    val isFolder: Boolean,
    val sharedWithMe: Boolean,
)

@Dao
interface AccountDao {
    @Query("SELECT id FROM accounts")
    suspend fun allIds(): List<String>

    @Upsert
    suspend fun upsert(account: AccountEntity)

    @Query("SELECT * FROM accounts WHERE id = :accountId AND isActive = 1 LIMIT 1")
    suspend fun findById(accountId: String): AccountEntity?

    @Query("SELECT * FROM accounts WHERE isActive = 1 ORDER BY displayName COLLATE NOCASE")
    suspend fun findActive(): List<AccountEntity>

    @Query("SELECT * FROM accounts WHERE isActive = 1 ORDER BY displayName COLLATE NOCASE")
    fun observeActive(): Flow<List<AccountEntity>>

    @Query("DELETE FROM accounts WHERE id = :accountId")
    suspend fun delete(accountId: String)
}

@Dao
interface SpaceDao {
    @Query("SELECT * FROM spaces WHERE accountId = :accountId AND isDeleted = 0 ORDER BY name COLLATE NOCASE")
    fun observeSpaces(accountId: String): Flow<List<SpaceEntity>>

    @Query("SELECT * FROM spaces WHERE accountId = :accountId AND isDeleted = 0 ORDER BY name COLLATE NOCASE")
    suspend fun findSpaces(accountId: String): List<SpaceEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(spaces: List<SpaceEntity>)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(space: SpaceEntity)

    @Query("SELECT COUNT(*) FROM spaces WHERE accountId = :accountId")
    suspend fun count(accountId: String): Int

    @Query("SELECT * FROM spaces WHERE accountId = :accountId AND driveId = :spaceId LIMIT 1")
    suspend fun findById(
        accountId: String,
        spaceId: String,
    ): SpaceEntity?

    @Delete
    suspend fun delete(space: SpaceEntity)

    @Query("DELETE FROM spaces WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)
}

@Dao
interface ResourceDao {
    @Query(
        "UPDATE resources SET path = :newPath || substr(path, length(:oldPath) + 1) " +
            "WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND substr(path, 1, length(:oldPath) + 1) = :oldPath || '/'",
    )
    suspend fun rebaseDescendants(
        accountId: String,
        spaceId: String,
        oldPath: String,
        newPath: String,
    )

    @Query("SELECT EXISTS(SELECT 1 FROM resources WHERE localPath = :path AND hasLocalCopy = 1)")
    suspend fun referencesCache(path: String): Boolean

    @Query(
        "UPDATE resources SET hasLocalCopy = 0, localPath = NULL WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path",
    )
    suspend fun invalidatePathCache(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query("SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path LIMIT 1")
    suspend fun findByPath(
        accountId: String,
        spaceId: String,
        path: String,
    ): ResourceEntity?

    @Query(
        "SELECT r.* FROM resources r JOIN spaces s ON s.accountId = r.accountId AND s.driveId = r.spaceId " +
            "JOIN accounts a ON a.id = r.accountId WHERE r.accountId = :accountId AND a.isActive = 1 " +
            "AND s.isDisabled = 0 AND s.isDeleted = 0 AND instr(lower(r.name), lower(:query)) > 0 " +
            "ORDER BY r.spaceId, r.remoteId LIMIT 100",
    )
    suspend fun providerSearch(
        accountId: String,
        query: String,
    ): List<ResourceEntity>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND isFavorite = 1 " +
            "ORDER BY CASE kind WHEN 'FOLDER' THEN 0 ELSE 1 END, name COLLATE NOCASE",
    )
    fun observeFavorites(accountId: String): Flow<List<ResourceEntity>>

    @Query(
        "SELECT r.* FROM resources r JOIN spaces s ON s.accountId = r.accountId AND s.driveId = r.spaceId " +
            "WHERE r.accountId = :accountId AND r.hasLocalCopy = 1 AND r.localPath IS NOT NULL " +
            "AND s.isDisabled = 0 AND s.isDeleted = 0 ORDER BY r.name COLLATE NOCASE",
    )
    fun observeOffline(accountId: String): Flow<List<ResourceEntity>>

    @Query(
        "SELECT r.* FROM resources r JOIN spaces s ON s.accountId = r.accountId AND s.driveId = r.spaceId " +
            "WHERE r.accountId = :accountId AND r.remoteId IN (:ids) AND s.isDisabled = 0 AND s.isDeleted = 0",
    )
    fun observeRecent(
        accountId: String,
        ids: List<String>,
    ): Flow<List<ResourceEntity>>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId " +
            "AND (name LIKE :pattern ESCAPE '\\' OR path LIKE :pattern ESCAPE '\\') " +
            "ORDER BY CASE kind WHEN 'FOLDER' THEN 0 ELSE 1 END, name COLLATE NOCASE",
    )
    fun search(
        accountId: String,
        pattern: String,
    ): Flow<List<ResourceEntity>>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND " +
            "((:parentId IS NULL AND parentId IS NULL) OR parentId = :parentId) " +
            "ORDER BY CASE kind WHEN 'FOLDER' THEN 0 ELSE 1 END, name COLLATE NOCASE",
    )
    fun observeChildren(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): Flow<List<ResourceEntity>>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND remoteId = :resourceId LIMIT 1",
    )
    suspend fun findById(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): ResourceEntity?

    @Query("SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId ORDER BY path COLLATE NOCASE")
    suspend fun findBySpace(
        accountId: String,
        spaceId: String,
    ): List<ResourceEntity>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND " +
            "((:parentId IS NULL AND parentId IS NULL) OR parentId = :parentId) " +
            "ORDER BY CASE kind WHEN 'FOLDER' THEN 0 ELSE 1 END, name COLLATE NOCASE",
    )
    suspend fun findChildren(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): List<ResourceEntity>

    @Query(
        "SELECT COUNT(*) FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND parentId IS :parentId",
    )
    suspend fun countChildren(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): Int

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId AND parentId IS :parentId " +
            "ORDER BY CASE kind WHEN 'FOLDER' THEN 0 ELSE 1 END, name COLLATE NOCASE, remoteId LIMIT 128 OFFSET :offset",
    )
    suspend fun childrenPage(
        accountId: String,
        spaceId: String,
        parentId: String?,
        offset: Int,
    ): List<ResourceEntity>

    @Query(
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND parentId IS :parentId AND name = :name LIMIT 1",
    )
    suspend fun findChild(
        accountId: String,
        spaceId: String,
        parentId: String?,
        name: String,
    ): ResourceEntity?

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(resource: ResourceEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(resource: ResourceEntity)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertAll(resources: List<ResourceEntity>)

    @Update
    suspend fun update(resource: ResourceEntity)

    @Query(
        "UPDATE resources SET hasLocalCopy = :hasLocalCopy, localPath = :localPath " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND remoteId = :resourceId",
    )
    @Suppress("LongParameterList")
    suspend fun updateLocalCopy(
        accountId: String,
        spaceId: String,
        resourceId: String,
        hasLocalCopy: Boolean,
        localPath: String?,
    )

    @Query(
        "UPDATE resources SET offlinePinned = :pinned " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND remoteId = :resourceId",
    )
    suspend fun setOfflinePinned(
        accountId: String,
        spaceId: String,
        resourceId: String,
        pinned: Boolean,
    )

    @Query(
        "UPDATE resources SET isFavorite = :favorite " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND remoteId = :resourceId",
    )
    suspend fun setFavorite(
        accountId: String,
        spaceId: String,
        resourceId: String,
        favorite: Boolean,
    )

    @Query("UPDATE resources SET isFavorite = 0 WHERE accountId = :accountId AND spaceId = :spaceId")
    suspend fun clearFavorites(
        accountId: String,
        spaceId: String,
    )

    @Query("SELECT * FROM resources WHERE offlinePinned = 1")
    suspend fun findOfflinePinned(): List<ResourceEntity>

    @Query("SELECT * FROM resources WHERE accountId = :accountId AND offlinePinned = 1")
    fun observeOfflinePins(accountId: String): Flow<List<ResourceEntity>>

    @Delete
    suspend fun delete(resource: ResourceEntity)

    @Query(
        "DELETE FROM resources WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND substr(path, 1, length(:pathPrefix)) = :pathPrefix",
    )
    suspend fun deleteDescendants(
        accountId: String,
        spaceId: String,
        pathPrefix: String,
    )

    @Query("DELETE FROM resources WHERE accountId = :accountId AND spaceId = :spaceId")
    suspend fun deleteAll(
        accountId: String,
        spaceId: String,
    )

    @Query("DELETE FROM resources WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)
}

private val PENDING_TRANSFER_STATES = setOf("QUEUED", "RUNNING", "RETRY")

@Dao
interface TransferDao {
    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND state IN ('QUEUED', 'RUNNING', 'RETRY') " +
            "AND (destinationPath = :path OR substr(destinationPath, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun cancelTree(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND state IN ('QUEUED', 'RUNNING', 'RETRY')",
    )
    suspend fun cancelSpace(
        accountId: String,
        spaceId: String,
    )

    @Query(
        "SELECT EXISTS(SELECT 1 FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
            "WHERE t.id != :id AND t.accountId = :account AND t.spaceId = :space " +
            "AND t.destinationPath = :path AND t.direction = 'UPLOAD' " +
            "AND (t.state = 'RUNNING' OR (t.state IN ('QUEUED', 'RETRY') " +
            "AND q.sequence < (SELECT sequence FROM transfer_queue WHERE transferId = :id))))",
    )
    suspend fun uploadDestinationBusy(
        id: String,
        account: String,
        space: String,
        path: String,
    ): Boolean

    @Transaction
    suspend fun retry(
        expected: TransferEntity,
        replacement: TransferEntity,
    ): TransferEntity? {
        val current = findById(expected.id)
        if (current == null ||
            current != expected ||
            current.state !in setOf("FAILED", "CANCELLED", "CONFLICT", "RETRY")
        ) {
            return null
        }
        require(replacement.id == current.id && replacement.state == "QUEUED")
        update(replacement)
        removeQueueEntry(current.id)
        insertQueueEntry(TransferQueueEntry(transferId = current.id))
        return replacement
    }

    @Query(
        "UPDATE transfers SET bytesTransferred = :bytes, updatedAtEpochMillis = :now, " +
            "verificationPending = CASE WHEN direction = 'UPLOAD' AND :bytes = bytesTotal " +
            "THEN 1 ELSE verificationPending END " +
            "WHERE id = :id AND workId = :workerId AND state = 'RUNNING'",
    )
    suspend fun updateProgress(
        id: String,
        workerId: String?,
        bytes: Long,
        now: Long,
    ): Int

    @Transaction
    suspend fun claim(
        id: String,
        workerId: String,
        now: Long,
    ): TransferEntity? {
        val current = findById(id)
        val ownedByAnotherWorker = current?.workId != null && current.workId != workerId
        if (current == null ||
            current.state !in PENDING_TRANSFER_STATES ||
            ownedByAnotherWorker
        ) {
            return null
        }
        val running = current.copy(state = TransferState.RUNNING.name, workId = workerId, updatedAtEpochMillis = now)
        val blocked =
            current.direction == "UPLOAD" &&
                uploadDestinationBusy(
                    current.id,
                    current.accountId,
                    current.spaceId,
                    current.destinationPath,
                )
        return if (blocked) {
            // This worker has not started network I/O. Release its persisted RUNNING marker
            // so overlapping intents left by an older process cannot wait on each other forever.
            if (current.state == TransferState.RUNNING.name) {
                update(current.copy(state = TransferState.RETRY.name, updatedAtEpochMillis = now))
            }
            null
        } else {
            update(running)
            running
        }
    }

    @Transaction
    suspend fun updateActive(transfer: TransferEntity): Boolean {
        val current = findById(transfer.id)
        if (current == null ||
            current.state !in PENDING_TRANSFER_STATES ||
            current.workId != transfer.workId
        ) {
            return false
        }
        update(transfer)
        return true
    }

    @Transaction
    suspend fun schedule(
        transfer: TransferEntity,
        workId: String,
        now: Long,
    ): Boolean {
        val current = findById(transfer.id)
        if (current == null ||
            current.state !in PENDING_TRANSFER_STATES ||
            current.workId != transfer.workId
        ) {
            return false
        }
        update(current.copy(workId = workId, updatedAtEpochMillis = now))
        return true
    }

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL WHERE id = :id AND state != 'SUCCEEDED'",
    )
    suspend fun cancel(id: String)

    @Query("SELECT * FROM transfers WHERE accountId = :accountId ORDER BY createdAtEpochMillis DESC")
    fun observeForAccount(accountId: String): Flow<List<TransferEntity>>

    @Query("SELECT * FROM transfers WHERE id = :id LIMIT 1")
    suspend fun findById(id: String): TransferEntity?

    @Query("SELECT * FROM transfers WHERE state IN ('QUEUED', 'RUNNING', 'RETRY')")
    suspend fun findPending(): List<TransferEntity>

    @Query("SELECT * FROM transfers WHERE accountId = :accountId")
    suspend fun findForAccount(accountId: String): List<TransferEntity>

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND resourceId = :resourceId AND direction = 'DOWNLOAD' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') LIMIT 1",
    )
    suspend fun findActiveDownload(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): TransferEntity?

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND resourceId = :resourceId AND direction = 'DOWNLOAD' " +
            "AND destinationPath = :path AND bytesTotal = :size " +
            "AND state IN ('FAILED', 'CONFLICT') LIMIT 1",
    )
    suspend fun findBlockedDownload(
        accountId: String,
        spaceId: String,
        resourceId: String,
        path: String,
        size: Long,
    ): TransferEntity?

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND sourceUri = :sourceUri AND destinationPath = :destinationPath AND direction = 'UPLOAD' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') LIMIT 1",
    )
    suspend fun findActiveUpload(
        accountId: String,
        spaceId: String,
        sourceUri: String,
        destinationPath: String,
    ): TransferEntity?

    @Transaction
    suspend fun insert(transfer: TransferEntity) {
        insertTransfer(transfer)
        insertQueueEntry(TransferQueueEntry(transferId = transfer.id))
    }

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertTransfer(transfer: TransferEntity)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertQueueEntry(entry: TransferQueueEntry)

    @Query("DELETE FROM transfer_queue WHERE transferId = :id")
    suspend fun removeQueueEntry(id: String)

    @Update
    suspend fun update(transfer: TransferEntity)

    @Query("DELETE FROM transfers WHERE accountId = :accountId AND state IN ('SUCCEEDED', 'CANCELLED')")
    suspend fun deleteHistory(accountId: String)

    @Query("DELETE FROM transfers WHERE accountId = :accountId")
    suspend fun deleteAllForAccount(accountId: String)

    @Query("SELECT * FROM transfers WHERE state = 'CONFLICT' ORDER BY updatedAtEpochMillis DESC")
    fun observeConflicts(): Flow<List<TransferEntity>>
}

@Dao
interface FolderBackupDao {
    @Query(
        "UPDATE folder_backups SET enabled = 0 WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND (:path IS NULL OR rtrim(destinationPath, '/') = :path " +
            "OR substr(destinationPath, 1, length(:path) + 1) = :path || '/' " +
            "OR substr(:path, 1, length(rtrim(destinationPath, '/')) + 1) = rtrim(destinationPath, '/') || '/')",
    )
    suspend fun disableVault(
        accountId: String,
        spaceId: String,
        path: String?,
    )

    @Query("SELECT * FROM folder_backups WHERE accountId = :accountId ORDER BY mediaType")
    fun observeForAccount(accountId: String): Flow<List<FolderBackupEntity>>

    @Query("SELECT * FROM folder_backups WHERE enabled = 1")
    suspend fun findEnabled(): List<FolderBackupEntity>

    @Query("SELECT * FROM folder_backups WHERE id = :id LIMIT 1")
    suspend fun findById(id: String): FolderBackupEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(configuration: FolderBackupEntity)

    @Query("DELETE FROM folder_backups WHERE id = :id")
    suspend fun delete(id: String)

    @Query("DELETE FROM folder_backups WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)
}

@Dao
interface ShareDao {
    @Query("SELECT * FROM shares WHERE accountId = :accountId ORDER BY sharedAtEpochSeconds DESC")
    fun observeForAccount(accountId: String): Flow<List<ShareEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(shares: List<ShareEntity>)

    @Query("DELETE FROM shares WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)

    @Query("DELETE FROM shares WHERE accountId = :accountId AND remoteId = :shareId")
    suspend fun delete(
        accountId: String,
        shareId: String,
    )
}

class FileBrowserStore(
    private val database: FileBrowserDatabase,
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
    ) = database.accountDao().upsert(
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

    fun observeTransfers(accountId: String): Flow<List<TransferEntity>> = transfers.observeForAccount(accountId)

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

    suspend fun retryTransfer(
        expected: TransferEntity,
        replacement: TransferEntity,
    ): TransferEntity? = database.retryAllowedTransfer(expected, replacement)

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

    suspend fun cancelTransfer(id: String) = transfers.cancel(id)

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
            database.snapshotVersions.begin(accountId)
            database.incomingShareVersions.begin(accountId)
            database.sharedFolderVersions.begin(accountId)
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

    suspend fun blockedDownload(resource: ResourceEntity): TransferEntity? =
        transfers.findBlockedDownload(
            resource.accountId,
            resource.spaceId,
            resource.remoteId,
            resource.path,
            resource.sizeBytes,
        )

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

    suspend fun clearTransferHistory(accountId: String) = transfers.deleteHistory(accountId)

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
    ): Boolean =
        database.withTransaction {
            require(snapshot.all { it.accountId == accountId })
            require(snapshot.map { it.driveId }.distinct().size == snapshot.size)
            require(excludedVaultIds.none { it.isBlank() })
            require(snapshot.none { it.driveId in excludedVaultIds })
            if (!database.snapshotVersions.accept(accountId, token)) return@withTransaction false
            val incomingIds = snapshot.mapTo(mutableSetOf()) { it.driveId }
            spaces.findSpaces(accountId).filterNot { it.driveId in incomingIds }.forEach { stale ->
                // Absence can mean revoked access, not deletion. Retain pins, cache and durable intent.
                spaces.upsertAll(listOf(stale.copy(isDisabled = true)))
            }
            spaces.upsertAll(snapshot)
            snapshot.forEach { database.vaultExclusionDao().confirmPlain(accountId, it.driveId, "") }
            if (excludedVaultIds.isNotEmpty()) database.snapshotVersions.begin(accountId)
            excludedVaultIds.forEach { spaceId ->
                database.excludeVaultDrive(accountId, spaceId)
            }
            true
        }

    private suspend fun rebaseMovedFolder(
        local: ResourceEntity?,
        remote: ResourceEntity,
    ) {
        if (local?.kind == ResourceKind.FOLDER && remote.kind == ResourceKind.FOLDER && local.path != remote.path) {
            database.snapshotVersions.begin(remote.accountId)
            resources.rebaseDescendants(remote.accountId, remote.spaceId, local.path, remote.path)
        }
    }

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
        database.withTransaction {
            val snapshot = discovered.resources
            require(snapshot.all { it.accountId == accountId && it.spaceId == spaceId && it.parentId == parentId })
            require(snapshot.map { it.remoteId }.distinct().size == snapshot.size)
            require(snapshot.map { it.path }.distinct().size == snapshot.size)
            require(snapshot.map { it.name }.distinct().size == snapshot.size)
            if (!database.snapshotVersions.accept(accountId, token, FolderSnapshotScope(spaceId, parentId))) {
                return@withTransaction false
            }
            database.reconcileVaultFolders(accountId, spaceId, parentId, discovered)
            snapshot.forEach { database.vaultExclusionDao().confirmPlain(accountId, spaceId, it.path.trimEnd('/')) }
            val existing = resources.findChildren(accountId, spaceId, parentId)
            val incomingIds = snapshot.mapTo(mutableSetOf()) { it.remoteId }
            existing.filterNot { it.remoteId in incomingIds }.forEach { stale ->
                if (stale.kind ==
                    ResourceKind.FOLDER
                ) {
                    database.snapshotVersions.begin(accountId)
                    resources.deleteDescendants(accountId, spaceId, "${stale.path.trimEnd('/')}/")
                }
                resources.delete(stale)
            }
            snapshot.forEach { remote ->
                val local = resources.findById(accountId, spaceId, remote.remoteId)
                rebaseMovedFolder(local, remote)
                val pendingPin = database.pendingPinDao().selected(accountId, spaceId, remote.path)
                val sameContent =
                    local?.eTag == remote.eTag &&
                        local?.sizeBytes == remote.sizeBytes &&
                        local?.kind == remote.kind
                resources.upsert(
                    remote.copy(
                        hasLocalCopy = sameContent && local?.hasLocalCopy == true,
                        localPath = local?.localPath?.takeIf { sameContent },
                        offlinePinned = pendingPin || local?.offlinePinned == true,
                        isFavorite = remote.isFavorite,
                    ),
                )
                if (pendingPin) database.pendingPinDao().acknowledge(accountId, spaceId, remote.path)
            }
            true
        }

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
