package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Update
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import java.util.UUID

@Entity(tableName = "offline_runs", indices = [Index(value = ["accountId", "spaceId", "rootId"], unique = true)])
data class OfflineRunEntity(
    @PrimaryKey val id: String,
    val accountId: String,
    val spaceId: String,
    val rootId: String,
    val state: String = "ACTIVE",
    val errorCode: String? = null,
)

@Entity(
    tableName = "offline_nodes",
    primaryKeys = ["runId", "resourceId"],
    foreignKeys = [
        ForeignKey(
            entity = OfflineRunEntity::class,
            parentColumns = ["id"],
            childColumns = ["runId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index(value = ["runId", "state", "resourceId"])],
)
data class OfflineNodeEntity(
    val runId: String,
    val resourceId: String,
    val state: String = "PENDING",
    val lastChildId: String? = null,
)

@Dao
interface OfflineTraversalDao {
    @Query(
        "UPDATE offline_runs SET state = 'CANCELLED' WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND state = 'ACTIVE' AND rootId IN (SELECT remoteId FROM resources " +
            "WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND (path = :path OR substr(path, 1, length(:path) + 1) = :path || '/'))",
    )
    suspend fun cancelTree(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query(
        "UPDATE offline_runs SET state = 'CANCELLED' WHERE accountId = :accountId AND spaceId = :spaceId AND state = 'ACTIVE'",
    )
    suspend fun cancelSpace(
        accountId: String,
        spaceId: String,
    )

    @Query("SELECT * FROM offline_runs WHERE id = :id")
    suspend fun run(id: String): OfflineRunEntity?

    @Query("SELECT * FROM offline_runs WHERE accountId = :account AND spaceId = :space AND rootId = :root")
    suspend fun forRoot(
        account: String,
        space: String,
        root: String,
    ): OfflineRunEntity?

    @Query("SELECT * FROM offline_runs WHERE state = 'ACTIVE'")
    suspend fun active(): List<OfflineRunEntity>

    @Query("SELECT * FROM offline_runs WHERE state = 'ACTIVE' AND (:after IS NULL OR id > :after) ORDER BY id LIMIT 32")
    suspend fun activePage(after: String?): List<OfflineRunEntity>

    @Insert
    suspend fun insertRun(run: OfflineRunEntity)

    @Query("DELETE FROM offline_runs WHERE id = :id")
    suspend fun deleteRun(id: String)

    @Query("DELETE FROM offline_runs WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)

    @Query(
        "UPDATE offline_runs SET state = 'CANCELLED' WHERE accountId = :account AND spaceId = :space " +
            "AND rootId = :root AND state = 'ACTIVE'",
    )
    suspend fun cancelRoot(
        account: String,
        space: String,
        root: String,
    )

    @Query("UPDATE offline_runs SET state = :state, errorCode = :errorCode WHERE id = :id AND state = 'ACTIVE'")
    suspend fun finish(
        id: String,
        state: String,
        errorCode: String? = null,
    )

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertNodes(nodes: List<OfflineNodeEntity>)

    @Update
    suspend fun updateNode(node: OfflineNodeEntity)

    @Query("SELECT * FROM offline_nodes WHERE runId = :runId AND state != 'DONE' ORDER BY resourceId LIMIT 1")
    suspend fun next(runId: String): OfflineNodeEntity?

    @Query("SELECT count(*) FROM offline_nodes WHERE runId = :runId")
    suspend fun count(runId: String): Int

    @Query(
        "SELECT * FROM resources WHERE accountId = :account AND spaceId = :space AND parentId = :parent " +
            "AND (:after IS NULL OR remoteId > :after) ORDER BY remoteId LIMIT 128",
    )
    suspend fun children(
        account: String,
        space: String,
        parent: String,
        after: String?,
    ): List<ResourceEntity>

    @Query(
        "SELECT r.* FROM resources r WHERE r.offlinePinned = 1 AND NOT EXISTS (" +
            "SELECT 1 FROM resources p WHERE p.accountId = r.accountId AND p.spaceId = r.spaceId " +
            "AND p.kind = 'FOLDER' AND p.offlinePinned = 1 AND p.remoteId != r.remoteId " +
            "AND substr(r.path, 1, length(rtrim(p.path, '/')) + 1) = rtrim(p.path, '/') || '/')",
    )
    suspend fun pinnedRoots(): List<ResourceEntity>

    @Query(
        "SELECT r.* FROM resources r WHERE r.offlinePinned = 1 AND " +
            "(:afterAccount IS NULL OR r.accountId > :afterAccount OR " +
            "(r.accountId = :afterAccount AND r.spaceId > :afterSpace) OR " +
            "(r.accountId = :afterAccount AND r.spaceId = :afterSpace AND r.remoteId > :afterResource)) " +
            "AND NOT EXISTS (SELECT 1 FROM resources p WHERE p.accountId = r.accountId AND p.spaceId = r.spaceId " +
            "AND p.kind = 'FOLDER' AND p.offlinePinned = 1 AND p.remoteId != r.remoteId " +
            "AND substr(r.path, 1, length(rtrim(p.path, '/')) + 1) = rtrim(p.path, '/') || '/') " +
            "ORDER BY r.accountId, r.spaceId, r.remoteId LIMIT 32",
    )
    suspend fun pinnedRootPage(
        afterAccount: String?,
        afterSpace: String?,
        afterResource: String?,
    ): List<ResourceEntity>

    @Query(
        "SELECT * FROM resources WHERE accountId = :account AND spaceId = :space AND offlinePinned = 1 " +
            "AND (remoteId = :root OR (kind = 'FOLDER' " +
            "AND substr(:path, 1, length(rtrim(path, '/')) + 1) = rtrim(path, '/') || '/')) " +
            "ORDER BY length(path), remoteId LIMIT 1",
    )
    suspend fun coveringRoot(
        account: String,
        space: String,
        root: String,
        path: String,
    ): ResourceEntity?

    @Query(
        "UPDATE offline_runs SET state = 'CANCELLED' WHERE accountId = :account AND spaceId = :space " +
            "AND state = 'ACTIVE' AND rootId != :root AND rootId IN (" +
            "SELECT remoteId FROM resources WHERE accountId = :account AND spaceId = :space " +
            "AND substr(path, 1, length(rtrim(:path, '/')) + 1) = rtrim(:path, '/') || '/')",
    )
    suspend fun cancelDescendants(
        account: String,
        space: String,
        root: String,
        path: String,
    )
}

class OfflineTraversalStore(
    private val database: FileBrowserDatabase,
) {
    val dao = database.offlineTraversalDao()

    suspend fun startIfSelected(root: ResourceEntity): OfflineRunEntity? =
        database.withTransaction {
            val current = database.resourceDao().findById(root.accountId, root.spaceId, root.remoteId)
            if (current?.offlinePinned == true) start(current) else null
        }

    /** Re-evaluate persisted active work against current selection without restarting completed work. */
    suspend fun reconcile(id: String): OfflineRunEntity? =
        database.withTransaction {
            val run = dao.run(id)?.takeIf { it.state == "ACTIVE" } ?: return@withTransaction null
            val root = database.resourceDao().findById(run.accountId, run.spaceId, run.rootId)
            if (root?.offlinePinned != true) {
                dao.finish(id, "CANCELLED")
                return@withTransaction null
            }
            start(root)
        }

    suspend fun start(root: ResourceEntity): OfflineRunEntity =
        database.withTransaction {
            val current = database.resourceDao().findById(root.accountId, root.spaceId, root.remoteId)
            require(current?.offlinePinned == true) { "The offline root is no longer selected." }
            val owner =
                requireNotNull(dao.coveringRoot(current.accountId, current.spaceId, current.remoteId, current.path))
            if (owner.kind == eu.opencloud.android.next.core.model.ResourceKind.FOLDER) {
                dao.cancelDescendants(owner.accountId, owner.spaceId, owner.remoteId, owner.path)
            }
            val existing = dao.forRoot(owner.accountId, owner.spaceId, owner.remoteId)
            if (existing?.state == "ACTIVE") return@withTransaction existing
            existing?.let { dao.deleteRun(it.id) }
            val run = OfflineRunEntity(UUID.randomUUID().toString(), owner.accountId, owner.spaceId, owner.remoteId)
            dao.insertRun(run)
            dao.insertNodes(listOf(OfflineNodeEntity(run.id, owner.remoteId)))
            run
        }

    /** Enqueue one stable-ID page and advance its cursor in one transaction. */
    suspend fun expand(
        run: OfflineRunEntity,
        node: OfflineNodeEntity,
    ) = database.withTransaction {
        if (dao.run(run.id)?.state != "ACTIVE") return@withTransaction
        val children = dao.children(run.accountId, run.spaceId, node.resourceId, node.lastChildId)
        require(dao.count(run.id) + children.size <= 100_001) { "Offline traversal exceeds the supported item limit." }
        dao.insertNodes(children.map { OfflineNodeEntity(run.id, it.remoteId) })
        dao.updateNode(
            node.copy(
                state = if (children.isEmpty()) "DONE" else "DISCOVERED",
                lastChildId =
                    children.lastOrNull()?.remoteId ?: node.lastChildId,
            ),
        )
    }
}

val MIGRATION_10_11 =
    object : Migration(10, 11) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS index_resources_offlinePinned_kind_accountId_spaceId " +
                    "ON resources(offlinePinned, kind, accountId, spaceId)",
            )
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS index_resources_accountId_spaceId_parentId_remoteId " +
                    "ON resources(accountId, spaceId, parentId, remoteId)",
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS offline_runs (id TEXT NOT NULL, accountId TEXT NOT NULL, " +
                    "spaceId TEXT NOT NULL, rootId TEXT NOT NULL, state TEXT NOT NULL, errorCode TEXT, PRIMARY KEY(id))",
            )
            db.execSQL(
                "CREATE UNIQUE INDEX IF NOT EXISTS index_offline_runs_accountId_spaceId_rootId " +
                    "ON offline_runs(accountId, spaceId, rootId)",
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS offline_nodes (runId TEXT NOT NULL, resourceId TEXT NOT NULL, " +
                    "state TEXT NOT NULL, lastChildId TEXT, PRIMARY KEY(runId, resourceId), " +
                    "FOREIGN KEY(runId) REFERENCES offline_runs(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS index_offline_nodes_runId_state_resourceId ON offline_nodes(runId, state, resourceId)",
            )
        }
    }
