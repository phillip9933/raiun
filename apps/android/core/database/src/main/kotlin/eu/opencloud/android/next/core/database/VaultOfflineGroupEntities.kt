package eu.opencloud.android.next.core.database

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "account_incarnations",
    foreignKeys = [
        ForeignKey(
            entity = AccountEntity::class,
            parentColumns = ["id"],
            childColumns = ["accountId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index(value = ["accountId", "incarnation"], unique = true)],
)
data class AccountIncarnationEntity(
    @PrimaryKey val accountId: String,
    val incarnation: String,
)

@Entity(
    tableName = "vault_offline_groups",
    foreignKeys = [
        ForeignKey(
            entity = AccountIncarnationEntity::class,
            parentColumns = ["accountId", "incarnation"],
            childColumns = ["accountId", "accountIncarnation"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["accountId", "state", "id"]),
        Index(value = ["accountId", "accountIncarnation", "id"], unique = true),
        Index(value = ["accountId", "driveId", "remoteVaultId", "activeSlot"], unique = true),
    ],
)
data class VaultOfflineGroupEntity(
    @PrimaryKey val id: String,
    val accountId: String,
    val accountIncarnation: String,
    val driveId: String,
    val remoteVaultId: String,
    val accountIdentityDigest: String,
    val identityDigest: String,
    val descriptorId: String,
    val descriptorDigest: String,
    val baseOfflineRootDigest: String,
    val planId: String,
    val sealedPlanDigest: String? = null,
    val sealedMemberCount: Long? = null,
    val sealedFileCount: Long? = null,
    val sealedCiphertextBytes: Long? = null,
    val stagedMemberCount: Long = 0,
    val stagingChainDigest: String,
    val state: String = "PREPARING",
    val revision: Long = 0,
    val attemptId: String? = null,
    val pendingPublicationId: String? = null,
    val activeSlot: Int? = 1,
    val errorCode: String? = null,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
)

@Entity(
    tableName = "vault_offline_group_members",
    primaryKeys = ["groupId", "sequence"],
    foreignKeys = [
        ForeignKey(
            entity = VaultOfflineGroupEntity::class,
            parentColumns = ["id"],
            childColumns = ["groupId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["memberId"], unique = true),
        Index(value = ["groupId", "state", "sequence"]),
    ],
)
data class VaultOfflineGroupMemberEntity(
    val groupId: String,
    val sequence: Long,
    val memberId: String,
    val descriptorDigest: String,
    val kind: String,
    val state: String,
    val revision: Long = 0,
    val attemptId: String? = null,
    val payloadId: String? = null,
    val checkpointBytes: Long = 0,
    val ciphertextDigest: String? = null,
    val errorCode: String? = null,
)

/** Independent of transfer/group history; only account-incarnation removal cascades authority. */
@Entity(
    tableName = "vault_offline_group_publications",
    foreignKeys = [
        ForeignKey(
            entity = AccountIncarnationEntity::class,
            parentColumns = ["accountId", "incarnation"],
            childColumns = ["accountId", "accountIncarnation"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["accountId", "accountIncarnation"]),
        Index(value = ["accountId", "journalResolved", "publicationId"]),
        Index(value = ["groupId", "publicationId"]),
    ],
)
data class VaultOfflineGroupPublicationEntity(
    @PrimaryKey val publicationId: String,
    val groupId: String,
    val accountId: String,
    val accountIncarnation: String,
    val identityDigest: String,
    val descriptorDigest: String,
    val sealedPlanDigest: String,
    val sealedMemberCount: Long,
    val baseOfflineRootDigest: String,
    val nextOfflineRootDigest: String,
    val reservedGroupRevision: Long,
    val state: String = "PREPARED",
    val journalResolved: Boolean = false,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
)
