package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.VaultGroupPublicationDecision
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Borrowed grants and the Store's existing locks govern capture and publication; no material is retained. */
@Suppress("LongParameterList") // These callbacks preserve the Store's existing account, lock and recovery authority.
internal class VaultOfflineGroupAccess(
    private val ownership: VaultOfflineOwnership,
    private val cipherFromMaterial: (ByteArray) -> VaultCipherEngine,
    private val requireAccount: suspend (VaultIdentity) -> Unit,
    private val beginPermit: (String) -> () -> Boolean,
    private val recoverPublication: suspend (VaultIdentity, VaultLocation, VaultOfflineGroups?) -> Unit,
    private val pinDirectory: suspend (VaultIdentity, VaultLocation, String, ByteArray, () -> Boolean) -> Unit,
    private val beforePublication: () -> Unit,
    private val afterPublication: () -> Unit,
) {
    // A verified plan, exact Room lease and current material grant form one publication claim.
    @Suppress("LongParameterList")
    suspend fun publishPreparedGroup(
        plan: VaultOfflineGroupVerifiedPlan,
        liveLocation: VaultLocation,
        material: ByteArray,
        expected: VaultGroupLease,
        groups: VaultOfflineGroups,
        livePermit: () -> Boolean,
        publicationAccepted: () -> Unit = {},
    ) = withContext(Dispatchers.IO) {
        requireLocation(plan.context.identity, liveLocation)
        requireAccount(plan.context.identity)
        val currentPermit = beginPermit(plan.context.identity.accountId)
        VaultOfflineGroupPublisher(
            ownership,
            cipherFromMaterial,
            {
                identity,
                location,
                ->
                recoverPublication(identity, location, groups)
            },
            beforePublication,
            afterPublication,
        ).publish(
            plan,
            liveLocation,
            material,
            expected,
            groups,
            { currentPermit() && livePermit() },
            publicationAccepted,
        )
    }

    suspend fun resolveUnjournaledGroupPublication(
        identity: VaultIdentity,
        location: VaultLocation,
        exact: VaultGroupPublication,
        groups: VaultOfflineGroups,
    ): VaultGroupPublicationDecision =
        withContext(Dispatchers.IO) {
            ownership.publicationLockFor(identity.accountId).withLock {
                ownership.lockFor(identity).withLock {
                    recoverPublication(identity, location, groups)
                    resolveOfflineGroupWithoutJournal(ownership, identity, exact, groups)
                }
            }
        }

    /** Reuses a proven committed anchor; a new user capture never rewrites an existing snapshot just to queue. */
    suspend fun ensureGroupAnchor(
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        additionalPermit: () -> Boolean,
    ): String =
        withContext(Dispatchers.IO) {
            requireLocation(identity, location)
            requireAccount(identity)
            val currentPermit = beginPermit(identity.accountId)
            val permit = { currentPermit() && additionalPermit() }
            val context = currentCoroutineContext()
            val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
            val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
            val checkActive = {
                checkOfflineGroupActive(
                    context,
                    permit,
                    identity,
                    accountGeneration,
                    identityGeneration,
                )
            }
            val access =
                VaultOfflineCommittedAccess(
                    ownership,
                    identity,
                    location,
                ) { recoverPublication(identity, location, null) }
            val revoked =
                ownership.accountRevoked(identity.accountId) ||
                    ownership.identityRevoked(identity) ||
                    VaultOfflineRevocations.accountBlocked(identity.accountId) ||
                    VaultOfflineRevocations.identityBlocked(identity)
            val existing = if (revoked) null else access.authenticatedAnchorDigest(material, checkActive)
            if (existing != null) return@withContext existing
            pinDirectory(identity, location, location.vaultPath, material, additionalPermit)
            access.authenticatedAnchorDigest(material, checkActive)
                ?: throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
        }
}

internal suspend fun VaultOfflineStore.ensureGroupAnchor(
    identity: VaultIdentity,
    location: VaultLocation,
    material: ByteArray,
    additionalPermit: () -> Boolean,
): String = groupAccess.ensureGroupAnchor(identity, location, material, additionalPermit)

@Suppress("LongParameterList") // One verified plan and exact publication grant cross this facade together.
internal suspend fun VaultOfflineStore.publishPreparedGroup(
    plan: VaultOfflineGroupVerifiedPlan,
    liveLocation: VaultLocation,
    material: ByteArray,
    expected: VaultGroupLease,
    groups: VaultOfflineGroups,
    livePermit: () -> Boolean,
    publicationAccepted: () -> Unit = {},
) =
    groupAccess.publishPreparedGroup(plan, liveLocation, material, expected, groups, livePermit, publicationAccepted)

internal suspend fun VaultOfflineStore.resolveUnjournaledGroupPublication(
    identity: VaultIdentity,
    location: VaultLocation,
    exact: VaultGroupPublication,
    groups: VaultOfflineGroups,
): VaultGroupPublicationDecision = groupAccess.resolveUnjournaledGroupPublication(identity, location, exact, groups)

private fun checkOfflineGroupActive(
    context: kotlin.coroutines.CoroutineContext,
    permit: () -> Boolean,
    identity: VaultIdentity,
    accountGeneration: Long,
    identityGeneration: Long,
) {
    context.ensureActive()
    val unchanged =
        accountGeneration == VaultOfflineRevocations.accountGeneration(identity.accountId) &&
            identityGeneration == VaultOfflineRevocations.identityGeneration(identity)
    if (!permit() || !unchanged) throw OpenCloudException(OpenCloudError.AccessDenied)
}
