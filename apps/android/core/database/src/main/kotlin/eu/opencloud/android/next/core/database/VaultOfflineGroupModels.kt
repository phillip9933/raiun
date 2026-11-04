package eu.opencloud.android.next.core.database

const val VAULT_GROUP_PAGE_SIZE = 128
const val VAULT_GROUP_LOCATION_KIND = "VAULT_GROUP"

data class VaultGroupOwner(
    val accountId: String,
    val incarnation: String,
    val accountIdentityDigest: String,
)

data class VaultGroupDescriptor(
    val groupId: String,
    val driveId: String,
    val remoteVaultId: String,
    val identityDigest: String,
    val descriptorId: String,
    val descriptorDigest: String,
    val baseOfflineRootDigest: String,
    val planId: String,
)

data class VaultGroupLease(
    val group: VaultOfflineGroupEntity,
    val parent: TransferEntity?,
)

data class VaultGroupAttempt(
    val lease: VaultGroupLease,
    val attemptId: String,
)

data class VaultGroupMemberAdmission(
    val sequence: Long,
    val memberId: String,
    val descriptorDigest: String,
    val kind: String,
    val payloadId: String? = null,
)

data class VaultGroupSeal(
    val planId: String,
    val digest: String,
    val memberCount: Long,
    val fileCount: Long,
    val ciphertextBytes: Long,
)

data class VaultGroupCheckpoint(
    val state: String,
    val checkpointBytes: Long,
    val ciphertextDigest: String? = null,
    val errorCode: String? = null,
)

data class VaultGroupCheckpointResult(
    val attempt: VaultGroupAttempt,
    val member: VaultOfflineGroupMemberEntity,
)

data class VaultGroupPublication(
    val publicationId: String,
    val groupId: String,
    val owner: VaultGroupOwner,
    val identityDigest: String,
    val descriptorDigest: String,
    val planDigest: String,
    val memberCount: Long,
    val baseRootDigest: String,
    val nextRootDigest: String,
)

data class VaultGroupPublicationReservation(
    val lease: VaultGroupLease,
    val publication: VaultGroupPublication,
    val receipt: VaultOfflineGroupPublicationEntity,
)

enum class VaultGroupPublicationDecision { ACCEPTED, REJECTED, UNKNOWN, REVOKED }
