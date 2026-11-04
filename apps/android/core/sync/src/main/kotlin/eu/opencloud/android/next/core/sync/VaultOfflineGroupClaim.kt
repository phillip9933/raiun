package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VaultGroupDescriptor
import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.database.VaultOfflineGroupEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity

internal fun validateOfflineGroupClaim(
    plan: VaultOfflineGroupVerifiedPlan,
    expected: VaultGroupLease,
    live: VaultLocation,
) {
    val context = plan.context
    val group = expected.group
    val owner = VaultGroupOwner(group.accountId, group.accountIncarnation, group.accountIdentityDigest)
    claim(owner == context.owner && context.location.matchesOfflineScope(live))
    claim(context.identity == VaultIdentity(live.accountId, live.canonicalServer, live.driveId, live.remoteVaultId))
    claim(group.descriptor() == context.descriptor())
    claim(group.state == "AWAITING_UNLOCK" && group.pendingPublicationId == null)
    claim(group.sealedPlanDigest == plan.seal.digest && group.sealedMemberCount == plan.seal.memberCount)
    claim(group.sealedFileCount == plan.seal.fileCount && group.sealedCiphertextBytes == plan.seal.ciphertextBytes)
    validateGroupParent(expected.parent ?: integrity(), context, plan.seal)
}

private fun VaultOfflineGroupEntity.descriptor() =
    VaultGroupDescriptor(
        id,
        driveId,
        remoteVaultId,
        identityDigest,
        descriptorId,
        descriptorDigest,
        baseOfflineRootDigest,
        planId,
    )

private fun validateGroupParent(
    parent: TransferEntity,
    context: VaultOfflineGroupContext,
    seal: VaultGroupSeal,
) {
    claim(parent.locationKind == "VAULT_GROUP" && parent.state == "AWAITING_UNLOCK" && parent.verificationPending)
    claim(
        parent.id == context.groupId &&
            parent.accountId == context.owner.accountId &&
            parent.spaceId == context.identity.driveId,
    )
    claim(parent.direction == "DOWNLOAD" && parent.offlinePin)
    claim(!parent.overwrite && !parent.deleteSourceAfterSuccess)
    claim(
        parent.sourceUri == "vault-offline-group:${context.identity.remoteVaultId}" &&
            parent.bytesTotal == seal.ciphertextBytes,
    )
    claim(parent.destinationPath == context.selectedEncryptedRoot && parent.resourceId == null)
}

private fun claim(valid: Boolean) {
    if (!valid) integrity()
}

private fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)
