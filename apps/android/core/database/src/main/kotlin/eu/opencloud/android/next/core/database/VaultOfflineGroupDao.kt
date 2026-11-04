package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

data class VaultGroupMemberCounts(
    val total: Long,
    val files: Long,
    val incomplete: Long,
    val bytes: Long,
)

@Dao
interface VaultOfflineGroupDao {
    @Query(
        "SELECT g.id || ':' || g.revision FROM vault_offline_groups g " +
            "JOIN accounts a ON a.id = g.accountId AND a.isActive = 1 " +
            "JOIN account_incarnations o ON o.accountId = g.accountId AND o.incarnation = g.accountIncarnation " +
            "WHERE g.accountId = :account AND g.driveId = :drive AND g.remoteVaultId = :vault " +
            "AND g.state = 'AWAITING_UNLOCK' ORDER BY g.id COLLATE BINARY LIMIT 1",
    )
    fun observeAwaiting(
        account: String,
        drive: String,
        vault: String,
    ): Flow<String?>

    @Query("SELECT * FROM accounts WHERE id = :accountId")
    suspend fun storedAccount(accountId: String): AccountEntity?

    @Query("SELECT * FROM account_incarnations WHERE accountId = :accountId")
    suspend fun owner(accountId: String): AccountIncarnationEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertOwner(owner: AccountIncarnationEntity): Long

    @Query("DELETE FROM account_incarnations WHERE accountId = :accountId")
    suspend fun deleteOwner(accountId: String)

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', workId = NULL, verificationPending = 0 " +
            "WHERE accountId = :accountId AND locationKind = 'VAULT_GROUP' " +
            "AND state IN ('QUEUED','RUNNING','RETRY','AWAITING_UNLOCK') " +
            "AND id IN (SELECT id FROM vault_offline_groups WHERE accountId = :accountId)",
    )
    suspend fun cancelOwnerTransfers(accountId: String)

    @Query("SELECT * FROM vault_offline_groups WHERE id = :id")
    suspend fun group(id: String): VaultOfflineGroupEntity?

    @Query(
        "SELECT * FROM vault_offline_groups WHERE accountId = :accountId AND driveId = :driveId " +
            "AND remoteVaultId = :vaultId AND (activeSlot = 1 OR pendingPublicationId IS NOT NULL) LIMIT 1",
    )
    suspend fun active(
        accountId: String,
        driveId: String,
        vaultId: String,
    ): VaultOfflineGroupEntity?

    @Insert suspend fun insertGroup(group: VaultOfflineGroupEntity)

    @Update suspend fun updateGroup(group: VaultOfflineGroupEntity)

    @Insert suspend fun insertMembers(members: List<VaultOfflineGroupMemberEntity>)

    @Update suspend fun updateMember(member: VaultOfflineGroupMemberEntity)

    @Query("SELECT * FROM vault_offline_group_members WHERE groupId = :groupId AND sequence = :sequence")
    suspend fun member(
        groupId: String,
        sequence: Long,
    ): VaultOfflineGroupMemberEntity?

    @Query(
        "SELECT * FROM vault_offline_group_members WHERE groupId = :groupId " +
            "AND (:after IS NULL OR sequence > :after) ORDER BY sequence LIMIT 128",
    )
    suspend fun members(
        groupId: String,
        after: Long?,
    ): List<VaultOfflineGroupMemberEntity>

    @Query(
        "SELECT COUNT(*) AS total, coalesce(SUM(CASE WHEN kind = 'FILE' THEN 1 ELSE 0 END),0) AS files, " +
            "coalesce(SUM(CASE WHEN state != 'DOWNLOADED' THEN 1 ELSE 0 END),0) AS incomplete, " +
            "coalesce(SUM(checkpointBytes),0) AS bytes FROM vault_offline_group_members WHERE groupId = :id",
    )
    suspend fun counts(id: String): VaultGroupMemberCounts

    @Query("SELECT * FROM vault_offline_group_publications WHERE publicationId = :id")
    suspend fun publication(id: String): VaultOfflineGroupPublicationEntity?

    @Insert suspend fun insertPublication(publication: VaultOfflineGroupPublicationEntity)

    @Update suspend fun updatePublication(publication: VaultOfflineGroupPublicationEntity)

    @Query(
        "SELECT EXISTS(SELECT 1 FROM vault_offline_group_publications WHERE accountId = :account " +
            "AND accountIncarnation = :incarnation AND identityDigest = :identity AND journalResolved = 0)",
    )
    suspend fun unresolved(
        account: String,
        incarnation: String,
        identity: String,
    ): Boolean

    @Query(
        "SELECT EXISTS(SELECT 1 FROM vault_offline_group_publications WHERE accountId = :account " +
            "AND accountIncarnation = :incarnation AND groupId = :groupId AND journalResolved = 0)",
    )
    suspend fun unresolvedGroup(
        account: String,
        incarnation: String,
        groupId: String,
    ): Boolean

    @Query(
        "SELECT * FROM vault_offline_groups WHERE accountId = :account AND accountIncarnation = :incarnation " +
            "AND (:after IS NULL OR id COLLATE BINARY > :after) ORDER BY id COLLATE BINARY LIMIT 128",
    )
    suspend fun groups(
        account: String,
        incarnation: String,
        after: String?,
    ): List<VaultOfflineGroupEntity>

    @Query(
        "SELECT * FROM vault_offline_group_publications WHERE accountId = :account " +
            "AND accountIncarnation = :incarnation AND journalResolved = 0 " +
            "AND (:after IS NULL OR publicationId COLLATE BINARY > :after) " +
            "ORDER BY publicationId COLLATE BINARY LIMIT 128",
    )
    suspend fun publications(
        account: String,
        incarnation: String,
        after: String?,
    ): List<VaultOfflineGroupPublicationEntity>
}
