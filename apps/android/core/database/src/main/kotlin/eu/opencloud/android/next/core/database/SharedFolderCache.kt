package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Upsert
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(
    tableName = "shared_folder_scopes",
    primaryKeys = ["accountId", "scopeId"],
    foreignKeys = [
        ForeignKey(
            entity = AccountEntity::class,
            parentColumns = ["id"],
            childColumns = ["accountId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedFolderScopeEntity(
    val accountId: String,
    val scopeId: String,
    val shareId: String,
    val serverDriveId: String,
    val rootItemId: String,
    val rootWebDavUrl: String,
)

@Entity(
    tableName = "shared_folder_entries",
    primaryKeys = ["accountId", "scopeId", "remoteId"],
    indices = [Index(value = ["accountId", "scopeId", "path"], unique = true)],
    foreignKeys = [
        ForeignKey(
            entity = SharedFolderScopeEntity::class,
            parentColumns = ["accountId", "scopeId"],
            childColumns = ["accountId", "scopeId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedFolderEntry(
    val accountId: String,
    val scopeId: String,
    val remoteId: String,
    val parentPath: String,
    val path: String,
    val name: String,
    val isFolder: Boolean,
    val mimeType: String?,
    val sizeBytes: Long,
    val eTag: String?,
    val modifiedAtEpochMillis: Long,
    val createdAtEpochMillis: Long,
)

data class SharedFolderListing(
    val entries: List<SharedFolderEntry>,
    val excludedVaultPaths: Set<String> = emptySet(),
    val plainCollectionConfirmed: Boolean = false,
)

data class SharedFolderSaveResult(
    val accepted: Boolean,
    val cleanupNeeded: Boolean,
)

@Entity(
    tableName = "shared_folder_pages",
    primaryKeys = ["accountId", "scopeId", "path"],
    foreignKeys = [
        ForeignKey(
            entity = SharedFolderScopeEntity::class,
            parentColumns = ["accountId", "scopeId"],
            childColumns = ["accountId", "scopeId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedFolderCachedPage(
    val accountId: String,
    val scopeId: String,
    val path: String,
)

/** Shared-listing vault evidence uses root-relative paths and outlives a temporarily removed share scope. */
@Entity(
    tableName = "shared_vault_exclusions",
    primaryKeys = ["accountId", "scopeId", "path"],
    foreignKeys = [
        ForeignKey(
            entity = AccountEntity::class,
            parentColumns = ["id"],
            childColumns = ["accountId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedVaultExclusion(
    val accountId: String,
    val scopeId: String,
    val path: String,
)

@Dao
interface SharedVaultExclusionDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun record(exclusion: SharedVaultExclusion)

    @Query(
        "SELECT EXISTS(SELECT 1 FROM shared_vault_exclusions WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND ((path = '/' AND substr(:path, 1, 1) = '/') OR " +
            "path = :path OR substr(:path, 1, length(path) + 1) = path || '/'))",
    )
    suspend fun denies(
        accountId: String,
        scopeId: String,
        path: String,
    ): Boolean

    @Query(
        "SELECT EXISTS(SELECT 1 FROM shared_vault_exclusions " +
            "WHERE accountId = :accountId AND scopeId = :scopeId AND path = :path)",
    )
    suspend fun exactlyExcluded(
        accountId: String,
        scopeId: String,
        path: String,
    ): Boolean

    @Query(
        "DELETE FROM shared_vault_exclusions WHERE accountId = :accountId AND scopeId = :scopeId AND path = :path",
    )
    suspend fun confirmPlain(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Query("DELETE FROM shared_vault_exclusions WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)
}

@Dao
interface SharedFolderCacheDao {
    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND locationKind = 'SHARED_FOLDER' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') AND spaceId IN " +
            "(SELECT scopeId FROM shared_folder_scopes WHERE accountId = :accountId AND serverDriveId = :driveId)",
    )
    suspend fun cancelDriveTransfers(
        accountId: String,
        driveId: String,
    )

    @Query("DELETE FROM shared_folder_scopes WHERE accountId = :accountId AND serverDriveId = :driveId")
    suspend fun excludeDrive(
        accountId: String,
        driveId: String,
    )

    @Query(
        "DELETE FROM shared_folder_scopes WHERE accountId = :accountId AND NOT EXISTS " +
            "(SELECT 1 FROM incoming_shares i WHERE i.accountId = shared_folder_scopes.accountId " +
            "AND i.id = shared_folder_scopes.shareId AND i.remoteId = shared_folder_scopes.rootItemId " +
            "AND i.isFolder = 1)",
    )
    suspend fun prune(accountId: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun markPage(page: SharedFolderCachedPage)

    @Query(
        "SELECT EXISTS(SELECT 1 FROM shared_folder_pages " +
            "WHERE accountId = :accountId AND scopeId = :scopeId AND path = :path)",
    )
    suspend fun hasPage(
        accountId: String,
        scopeId: String,
        path: String,
    ): Boolean

    @Query(
        "DELETE FROM shared_folder_pages WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND ((:path = '/' AND substr(path, 1, 1) = '/') OR " +
            "path = :path OR substr(path, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun clearPages(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Query("SELECT * FROM shared_folder_scopes WHERE accountId = :accountId AND scopeId = :scopeId")
    suspend fun scope(
        accountId: String,
        scopeId: String,
    ): SharedFolderScopeEntity?

    @Query("SELECT * FROM shared_folder_entries WHERE accountId = :accountId AND scopeId = :scopeId AND remoteId = :id")
    suspend fun entry(
        accountId: String,
        scopeId: String,
        id: String,
    ): SharedFolderEntry?

    @Upsert suspend fun saveScope(scope: SharedFolderScopeEntity)

    @Query(
        "SELECT * FROM shared_folder_entries WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND parentPath = :path ORDER BY name, remoteId",
    )
    suspend fun children(
        accountId: String,
        scopeId: String,
        path: String,
    ): List<SharedFolderEntry>

    @Query(
        "DELETE FROM shared_folder_entries WHERE accountId = :accountId AND scopeId = :scopeId AND parentPath = :path",
    )
    suspend fun clearChildren(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Query(
        "DELETE FROM shared_folder_entries WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND substr(path, 1, length(:prefix)) = :prefix",
    )
    suspend fun clearDescendants(
        accountId: String,
        scopeId: String,
        prefix: String,
    )

    @Query(
        "DELETE FROM shared_folder_entries WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND ((:path = '/' AND substr(path, 1, 1) = '/') OR " +
            "path = :path OR substr(path, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun clearSubtree(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND spaceId = :scopeId AND locationKind = 'SHARED_FOLDER' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') AND ((direction = 'DOWNLOAD' AND id IN " +
            "(SELECT transferId FROM shared_download_intents WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND ((:path = '/' AND substr(path, 1, 1) = '/') OR path = :path OR " +
            "substr(path, 1, length(:path) + 1) = :path || '/'))) OR " +
            "(direction = 'UPLOAD' AND ((:path = '/' AND substr(destinationPath, 1, 1) = '/') OR " +
            "destinationPath = :path OR " +
            "substr(destinationPath, 1, length(:path) + 1) = :path || '/'))) ",
    )
    suspend fun cancelSubtreeTransfers(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Query(
        "DELETE FROM shared_download_intents WHERE accountId = :accountId AND scopeId = :scopeId " +
            "AND ((:path = '/' AND substr(path, 1, 1) = '/') OR " +
            "path = :path OR substr(path, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun clearSubtreeDownloadIntents(
        accountId: String,
        scopeId: String,
        path: String,
    )

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entries: List<SharedFolderEntry>)
}

/** Cache metadata only. A current local lease is necessary, but fresh server access is a caller precondition. */
class SharedFolderCacheStore(
    private val database: FileBrowserDatabase,
) {
    private val inventory = IncomingShareStore(database)
    private val dao = database.sharedFolderCacheDao()
    private val exclusions = database.sharedVaultExclusionDao()

    /** Fresh local authority check for a root-relative shared path, including saved vault evidence. */
    suspend fun isAllowed(
        lease: IncomingShareLease,
        scope: SharedFolderScopeEntity,
        path: String,
        requireCachedPage: Boolean = false,
    ): Boolean =
        database.withTransaction {
            requireBinding(lease, scope)
            inventory.isCurrent(lease) &&
                dao.scope(scope.accountId, scope.scopeId) == scope &&
                !driveExcluded(scope) &&
                !exclusions.denies(scope.accountId, scope.scopeId, path) &&
                (!requireCachedPage || dao.hasPage(scope.accountId, scope.scopeId, path))
        }

    suspend fun begin(
        lease: IncomingShareLease,
        scope: SharedFolderScopeEntity,
        path: String,
    ): SnapshotToken? =
        database.withTransaction {
            requireBinding(lease, scope)
            if (driveExcluded(scope) || deniedOutsideRootProbe(scope, path)) {
                return@withTransaction null
            }
            if (!inventory.isCurrent(lease)) return@withTransaction null
            database.sharedFolderVersions.beginFolder(scope.accountId, FolderSnapshotScope(scope.scopeId, path))
        }

    suspend fun save(
        lease: IncomingShareLease,
        token: SnapshotToken,
        scope: SharedFolderScopeEntity,
        path: String,
        entries: List<SharedFolderEntry>,
    ): Boolean = save(lease, token, scope, path, SharedFolderListing(entries))

    suspend fun save(
        lease: IncomingShareLease,
        token: SnapshotToken,
        scope: SharedFolderScopeEntity,
        path: String,
        listing: SharedFolderListing,
    ): Boolean = saveAndReport(lease, token, scope, path, listing).accepted

    suspend fun saveAndReport(
        lease: IncomingShareLease,
        token: SnapshotToken,
        scope: SharedFolderScopeEntity,
        path: String,
        listing: SharedFolderListing,
    ): SharedFolderSaveResult =
        database.withTransaction {
            requireBinding(lease, scope)
            if (driveExcluded(scope) || deniedOutsideRootProbe(scope, path)) {
                return@withTransaction SharedFolderSaveResult(false, false)
            }
            if (requiresRootConfirmation(scope, path, listing)) {
                return@withTransaction SharedFolderSaveResult(false, false)
            }
            validateListing(scope, path, listing)
            if (!acceptSnapshot(lease, token, scope, path)) {
                return@withTransaction SharedFolderSaveResult(false, false)
            }
            val existing = dao.scope(scope.accountId, scope.scopeId)
            require(existing == null || existing == scope)
            dao.saveScope(scope)
            val vaultCleanupNeeded = applyVaultEvidence(scope, path, listing)
            val reconciliationCleanupNeeded = reconcileChildren(scope, path, listing.entries)
            val cleanupNeeded = vaultCleanupNeeded || reconciliationCleanupNeeded
            dao.clearChildren(scope.accountId, scope.scopeId, path)
            dao.insert(listing.entries)
            if (path !in listing.excludedVaultPaths) {
                dao.markPage(SharedFolderCachedPage(scope.accountId, scope.scopeId, path))
            }
            SharedFolderSaveResult(true, cleanupNeeded)
        }

    private suspend fun validateListing(
        scope: SharedFolderScopeEntity,
        path: String,
        listing: SharedFolderListing,
    ) {
        val entries = listing.entries
        val excludedPaths = listing.excludedVaultPaths
        require(entries.all { it.accountId == scope.accountId && it.scopeId == scope.scopeId && it.parentPath == path })
        require(entries.map { it.remoteId }.distinct().size == entries.size)
        require(entries.map { it.path }.distinct().size == entries.size)
        require(excludedPaths.all { it.isImmediateOrRequestedExclusion(path) })
        require(excludedPaths.none { it == path } || entries.isEmpty())
        require(entries.none { item -> excludedPaths.any { item.path == it || item.path.startsWith("$it/") } })
        require(entries.all { it.remoteId.isNotBlank() && it.path.substringBeforeLast('/').ifEmpty { "/" } == path })
        val rootProbe =
            path == "/" &&
                listing.plainCollectionConfirmed &&
                exclusions.exactlyExcluded(scope.accountId, scope.scopeId, "/")
        require(
            entries.all { item ->
                !exclusions.denies(scope.accountId, scope.scopeId, item.path) ||
                    exclusions.exactlyExcluded(scope.accountId, scope.scopeId, item.path) ||
                    rootProbe
            },
        )
    }

    private suspend fun acceptSnapshot(
        lease: IncomingShareLease,
        token: SnapshotToken,
        scope: SharedFolderScopeEntity,
        path: String,
    ): Boolean =
        inventory.isCurrent(lease) &&
            database.sharedFolderVersions.accept(
                scope.accountId,
                token,
                FolderSnapshotScope(scope.scopeId, path),
            )

    private suspend fun applyVaultEvidence(
        scope: SharedFolderScopeEntity,
        path: String,
        listing: SharedFolderListing,
    ): Boolean {
        listing.entries.forEach { exclusions.confirmPlain(scope.accountId, scope.scopeId, it.path) }
        if (path == "/" && "/" !in listing.excludedVaultPaths && listing.plainCollectionConfirmed) {
            exclusions.confirmPlain(scope.accountId, scope.scopeId, "/")
        }
        listing.excludedVaultPaths.forEach { path ->
            exclusions.record(SharedVaultExclusion(scope.accountId, scope.scopeId, path))
            revokeSubtree(scope, path)
        }
        return listing.excludedVaultPaths.isNotEmpty()
    }

    private suspend fun reconcileChildren(
        scope: SharedFolderScopeEntity,
        path: String,
        entries: List<SharedFolderEntry>,
    ): Boolean {
        val relocatedPaths = mutableSetOf<String>()
        entries.forEach { item ->
            val previous = dao.entry(scope.accountId, scope.scopeId, item.remoteId)
            if (previous != null && !previous.unchangedAs(item)) {
                relocatedPaths += previous.path
                revokeSubtree(scope, previous.path)
            }
        }
        var staleStateRevoked = relocatedPaths.isNotEmpty()
        dao.children(scope.accountId, scope.scopeId, path).forEach { old ->
            val replacement = entries.singleOrNull { it.remoteId == old.remoteId }
            if (old.path !in relocatedPaths && !old.unchangedAs(replacement)) {
                revokeSubtree(scope, old.path)
                staleStateRevoked = true
            }
        }
        return staleStateRevoked
    }

    private suspend fun revokeSubtree(
        scope: SharedFolderScopeEntity,
        path: String,
    ) {
        database.sharedFolderVersions.begin(scope.accountId)
        dao.cancelSubtreeTransfers(scope.accountId, scope.scopeId, path)
        dao.clearSubtreeDownloadIntents(scope.accountId, scope.scopeId, path)
        dao.clearSubtree(scope.accountId, scope.scopeId, path)
        dao.clearPages(scope.accountId, scope.scopeId, path)
        database.sharedLocalFileDao().deleteSubtree(scope.accountId, scope.scopeId, path)
    }

    suspend fun read(
        lease: IncomingShareLease,
        scope: SharedFolderScopeEntity,
        path: String,
    ): List<SharedFolderEntry>? =
        database.withTransaction {
            requireBinding(lease, scope)
            if (driveExcluded(scope) || exclusions.denies(scope.accountId, scope.scopeId, path)) {
                return@withTransaction null
            }
            if (!inventory.isCurrent(lease) || dao.scope(scope.accountId, scope.scopeId) != scope) {
                return@withTransaction null
            }
            if (dao.hasPage(scope.accountId, scope.scopeId, path)) {
                dao.children(scope.accountId, scope.scopeId, path)
            } else {
                null
            }
        }

    private fun requireBinding(
        lease: IncomingShareLease,
        scope: SharedFolderScopeEntity,
    ) {
        require(lease.share.isFolder)
        require(
            scope.accountId == lease.account.id &&
                scope.shareId == lease.share.id &&
                scope.rootItemId == lease.share.remoteId,
        )
    }

    private suspend fun driveExcluded(scope: SharedFolderScopeEntity): Boolean =
        database.vaultExclusionDao().denies(scope.accountId, scope.serverDriveId, "")

    private suspend fun deniedOutsideRootProbe(
        scope: SharedFolderScopeEntity,
        path: String,
    ): Boolean {
        if (!exclusions.denies(scope.accountId, scope.scopeId, path)) return false
        return path != "/" || !exclusions.exactlyExcluded(scope.accountId, scope.scopeId, "/")
    }

    private suspend fun requiresRootConfirmation(
        scope: SharedFolderScopeEntity,
        path: String,
        listing: SharedFolderListing,
    ): Boolean =
        path == "/" &&
            exclusions.exactlyExcluded(scope.accountId, scope.scopeId, "/") &&
            "/" !in listing.excludedVaultPaths &&
            !listing.plainCollectionConfirmed
}

private fun String.isSharedVaultPath(): Boolean {
    if (!startsWith('/') || this == "/") return false
    val segments = drop(1).split('/')
    return segments.all { segment ->
        segment.isNotBlank() &&
            segment !in setOf(".", "..") &&
            segment.none { it == '\\' || it.code < 32 || it.code == 127 }
    }
}

private fun String.isImmediateOrRequestedExclusion(path: String): Boolean =
    this == path || (isSharedVaultPath() && substringBeforeLast('/').ifEmpty { "/" } == path)

private fun SharedFolderEntry.unchangedAs(other: SharedFolderEntry?): Boolean =
    other != null &&
        other.path == path &&
        other.isFolder == isFolder &&
        (isFolder || (other.sizeBytes == sizeBytes && other.eTag == eTag))

val MIGRATION_17_18 =
    object : Migration(17, 18) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_folder_scopes (accountId TEXT NOT NULL, scopeId TEXT NOT NULL, " +
                    "shareId TEXT NOT NULL, serverDriveId TEXT NOT NULL, rootItemId TEXT NOT NULL, " +
                    "rootWebDavUrl TEXT NOT NULL, " +
                    "PRIMARY KEY(accountId, scopeId), " +
                    "FOREIGN KEY(accountId) REFERENCES accounts(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_folder_entries (accountId TEXT NOT NULL, scopeId TEXT NOT NULL, " +
                    "remoteId TEXT NOT NULL, parentPath TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL, " +
                    "isFolder INTEGER NOT NULL, mimeType TEXT, sizeBytes INTEGER NOT NULL, eTag TEXT, " +
                    "modifiedAtEpochMillis INTEGER NOT NULL, createdAtEpochMillis INTEGER NOT NULL, " +
                    "PRIMARY KEY(accountId, scopeId, remoteId), FOREIGN KEY(accountId, scopeId) " +
                    "REFERENCES shared_folder_scopes(accountId, scopeId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL(
                "CREATE UNIQUE INDEX IF NOT EXISTS index_shared_folder_entries_accountId_scopeId_path " +
                    "ON shared_folder_entries(accountId, scopeId, path)",
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_folder_pages (accountId TEXT NOT NULL, scopeId TEXT NOT NULL, " +
                    "path TEXT NOT NULL, PRIMARY KEY(accountId, scopeId, path), FOREIGN KEY(accountId, scopeId) " +
                    "REFERENCES shared_folder_scopes(accountId, scopeId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
        }
    }

val MIGRATION_22_23 =
    object : Migration(22, 23) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_vault_exclusions (accountId TEXT NOT NULL, scopeId TEXT NOT NULL, " +
                    "path TEXT NOT NULL, PRIMARY KEY(accountId, scopeId, path), " +
                    "FOREIGN KEY(accountId) REFERENCES accounts(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
        }
    }
