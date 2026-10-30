package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VaultGroupDescriptor
import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.database.VaultOfflineGroupPublicationEntity
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

suspend fun VaultSession.completePendingOfflineGroups(
    context: Context,
    offline: VaultOfflineStore,
) = withGroupMaterial { material, permit, accepted ->
    completeVaultPendingGroups(context, identity, location, material, offline, permit, accepted)
}

suspend fun VaultOfflineSession.completePendingOfflineGroups(
    context: Context,
    offline: VaultOfflineStore,
) = withGroupMaterial { material, permit, accepted ->
    completeVaultPendingGroups(context, identity, location, material, offline, permit, accepted)
}

/** Room progress is only a transport hint. Private authenticated membership and blocks own publication. */
@Suppress("LongParameterList", "TooGenericExceptionCaught")
internal suspend fun completeVaultPendingGroups(
    context: Context,
    identity: VaultIdentity,
    location: VaultLocation,
    material: ByteArray,
    offline: VaultOfflineStore,
    livePermit: () -> Boolean,
    publicationAccepted: () -> Unit,
) = withContext(Dispatchers.IO) {
    val groups = FileBrowserStore(FileBrowserDatabase.create(context)).vaultOfflineGroups()
    val owner =
        groups.captureOwner(identity.accountId) ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
    val accountLease = AccountSessions.get(context).beginLease(identity.accountId)
    val coroutine = currentCoroutineContext()
    val permit = {
        coroutine.ensureActive()
        livePermit() && accountLease()
    }
    if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
    val plans = VaultOfflineGroupPlanStore(context)
    resolveGroupReceipts(groups, owner, plans, identity, location, offline, permit)
    val expected = groups.active(owner, identity.driveId, identity.remoteVaultId) ?: return@withContext
    if (expected.group.state != "AWAITING_UNLOCK") return@withContext
    try {
        plans.open(owner, expected.group.id).use { opaque ->
            requireGroupPublicationPlan(opaque, identity, owner, expected)
            val frozen = opaque.context
            opaque
                .verify(material, frozen) {
                    if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                }.use { verified ->
                    offline.publishPreparedGroup(
                        verified,
                        location,
                        material,
                        expected,
                        groups,
                        permit,
                        publicationAccepted,
                    )
                }
        }
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (failure: Exception) {
        val error = failure.toOpenCloudError()
        if (error !in
            setOf(
                OpenCloudError.AccessDenied,
                OpenCloudError.AuthenticationRequired,
                OpenCloudError.EncryptedUnlockFailed,
            )
        ) {
            // A publisher reservation may already own recovery. Never erase or reinterpret it here.
            if (expected.group.pendingPublicationId == null && groups.isCurrent(expected)) {
                groups.fail(
                    expected,
                    error.diagnosticCode(),
                    System.currentTimeMillis(),
                    message = error.safeMessage(context),
                )
            }
        }
        throw failure
    }
}

@Suppress("LongParameterList") // Exact account and vault scope accompany the bounded receipt scan.
private suspend fun resolveGroupReceipts(
    groups: VaultOfflineGroups,
    owner: VaultGroupOwner,
    plans: VaultOfflineGroupPlanStore,
    identity: VaultIdentity,
    location: VaultLocation,
    offline: VaultOfflineStore,
    permit: () -> Boolean,
) {
    var after: String? = null
    while (true) {
        val page = groups.unresolvedPublicationPage(owner, after)
        if (page.isEmpty()) return
        for (receipt in page) {
            if (receipt.identityDigest != VaultOfflineGroupPlanCodec.digest(identityBytes(identity))) continue
            if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            resolveRetainedGroupReceipt(plans, owner, receipt, identity) { exact ->
                offline.resolveUnjournaledGroupPublication(identity, location, exact, groups)
            }
        }
        after = page.last().publicationId
    }
}

private fun requireGroupPublicationPlan(
    plan: VaultOfflineGroupOpaquePlan,
    identity: VaultIdentity,
    owner: VaultGroupOwner,
    expected: VaultGroupLease,
) {
    val frozen = plan.context
    if (frozen.identity != identity || frozen.owner != owner) groupPublicationIntegrity()
    val row = expected.group
    val descriptor =
        VaultGroupDescriptor(
            row.id,
            row.driveId,
            row.remoteVaultId,
            row.identityDigest,
            row.descriptorId,
            row.descriptorDigest,
            row.baseOfflineRootDigest,
            row.planId,
        )
    val seal =
        VaultGroupSeal(
            row.planId,
            row.sealedPlanDigest ?: groupPublicationIntegrity(),
            row.sealedMemberCount ?: groupPublicationIntegrity(),
            row.sealedFileCount ?: groupPublicationIntegrity(),
            row.sealedCiphertextBytes ?: groupPublicationIntegrity(),
        )
    if (frozen.descriptor() != descriptor || plan.seal != seal) groupPublicationIntegrity()
}

private suspend fun resolveRetainedGroupReceipt(
    plans: VaultOfflineGroupPlanStore,
    owner: VaultGroupOwner,
    receipt: VaultOfflineGroupPublicationEntity,
    identity: VaultIdentity,
    resolve: suspend (VaultGroupPublication) -> Unit,
) {
    plans.open(owner, receipt.groupId).use { plan ->
        val matches =
            plan.context.identity == identity &&
                plan.context.descriptorDigest == receipt.descriptorDigest &&
                plan.seal.digest == receipt.sealedPlanDigest
        if (matches) resolve(receipt.exact(owner))
    }
}

private fun groupPublicationIntegrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)

private fun VaultOfflineGroupPublicationEntity.exact(owner: VaultGroupOwner) =
    VaultGroupPublication(
        publicationId,
        groupId,
        owner,
        identityDigest,
        descriptorDigest,
        sealedPlanDigest,
        sealedMemberCount,
        baseOfflineRootDigest,
        nextOfflineRootDigest,
    )
