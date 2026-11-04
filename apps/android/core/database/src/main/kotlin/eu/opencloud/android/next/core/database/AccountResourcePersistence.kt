package eu.opencloud.android.next.core.database

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.TypeConverter
import androidx.room.Update
import androidx.room.Upsert
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.flow.Flow

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
    @ColumnInfo(defaultValue = "0") val removalPending: Boolean = false,
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

@Dao
interface AccountDao {
    @Query("SELECT * FROM accounts WHERE removalPending = 1")
    suspend fun pendingRemovals(): List<AccountEntity>

    @Query("SELECT COUNT(*) FROM accounts WHERE removalPending = 1")
    fun observePendingRemovalCount(): Flow<Int>

    @Query("SELECT * FROM accounts WHERE id = :accountId LIMIT 1")
    suspend fun stored(accountId: String): AccountEntity?

    @Query("UPDATE accounts SET removalPending = 1, isActive = 0 WHERE id = :accountId")
    suspend fun markRemoving(accountId: String)

    @Query("SELECT * FROM accounts")
    suspend fun all(): List<AccountEntity>

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
    @androidx.room.RawQuery(
        observedEntities = [ResourceEntity::class, VaultExclusion::class, AccountEntity::class, SpaceEntity::class],
    )
    fun observeDirectoryInvalidation(query: androidx.sqlite.db.SupportSQLiteQuery): Flow<Int>

    @androidx.room.RawQuery
    suspend fun directoryCount(query: androidx.sqlite.db.SupportSQLiteQuery): Int

    @androidx.room.RawQuery
    suspend fun directoryRows(query: androidx.sqlite.db.SupportSQLiteQuery): List<ResourceDirectoryRow>

    @androidx.room.RawQuery
    suspend fun collectionRows(query: androidx.sqlite.db.SupportSQLiteQuery): List<ResourceCollectionRow>

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
            "AND NOT EXISTS (SELECT 1 FROM vault_exclusions v WHERE v.accountId = r.accountId " +
            "AND v.spaceId = r.spaceId AND (v.path = '' OR v.path = rtrim(r.path, '/') " +
            "OR substr(r.path, 1, length(v.path) + 1) = v.path || '/')) " +
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
        "SELECT * FROM resources WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND parentId IS :parentId AND remoteId > :afterId ORDER BY remoteId LIMIT 128",
    )
    suspend fun childrenAfterId(
        accountId: String,
        spaceId: String,
        parentId: String?,
        afterId: String,
    ): List<ResourceEntity>

    @Query(
        "SELECT COUNT(*) FROM resources r WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND parentId IS :parentId " +
            "AND NOT EXISTS (SELECT 1 FROM vault_exclusions v WHERE v.accountId = r.accountId " +
            "AND v.spaceId = r.spaceId AND (v.path = '' OR v.path = rtrim(r.path, '/') " +
            "OR substr(r.path, 1, length(v.path) + 1) = v.path || '/')) ",
    )
    suspend fun countChildren(
        accountId: String,
        spaceId: String,
        parentId: String?,
    ): Int

    @Query(
        "SELECT r.* FROM resources r WHERE accountId = :accountId AND spaceId = :spaceId AND parentId IS :parentId " +
            "AND NOT EXISTS (SELECT 1 FROM vault_exclusions v WHERE v.accountId = r.accountId " +
            "AND v.spaceId = r.spaceId AND (v.path = '' OR v.path = rtrim(r.path, '/') " +
            "OR substr(r.path, 1, length(v.path) + 1) = v.path || '/')) " +
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
