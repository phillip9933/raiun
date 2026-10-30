package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupDescriptor
import eu.opencloud.android.next.core.database.VaultGroupMemberAdmission
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity

/** Child paths remain original encrypted DAV paths. No display labels or authentication grants persist. */
internal data class VaultOfflineGroupContext(
    val groupId: String,
    val owner: VaultGroupOwner,
    val identity: VaultIdentity,
    val location: VaultLocation,
    val selectedEncryptedRoot: String,
    val rootProofDigest: String?,
    val baseOfflineRootDigest: String,
) {
    val descriptorDigest: String by lazy { VaultOfflineGroupPlanCodec.digest(VaultOfflineGroupPlanCodec.context(this)) }
    val identityDigest: String by lazy { VaultOfflineGroupPlanCodec.digest(identityBytes(identity)) }

    fun descriptor(): VaultGroupDescriptor =
        VaultGroupDescriptor(
            groupId,
            identity.driveId,
            identity.remoteVaultId,
            identityDigest,
            groupId,
            descriptorDigest,
            baseOfflineRootDigest,
            groupId,
        )
}

internal enum class VaultOfflineGroupMemberKind { DIRECTORY, FILE }

internal data class VaultOfflineGroupMember(
    val sequence: Long,
    val id: String,
    val kind: VaultOfflineGroupMemberKind,
    val source: VaultDavEntry,
    val payloadId: String?,
    val payloadDescriptorDigest: String?,
    val descriptorDigest: String,
) {
    fun admission(): VaultGroupMemberAdmission =
        VaultGroupMemberAdmission(sequence, id, descriptorDigest, kind.name, payloadId)
}

/** The final proof type has a private constructor and a nonvirtual authenticating factory. */
internal typealias VaultOfflineGroupVerifiedPlan = VaultOfflineGroupPlanStore.VerifiedPlan

internal interface VaultOfflineGroupOpaquePlan : AutoCloseable {
    val context: VaultOfflineGroupContext
    val seal: VaultGroupSeal

    fun page(
        afterSequence: Long? = null,
        limit: Int = 128,
    ): List<VaultOfflineGroupMember>

    fun fileJob(member: VaultOfflineGroupMember): VaultDownloadJob

    fun verify(
        material: ByteArray,
        expectedContext: VaultOfflineGroupContext,
        checkActive: () -> Unit = {},
    ): VaultOfflineGroupVerifiedPlan
}
