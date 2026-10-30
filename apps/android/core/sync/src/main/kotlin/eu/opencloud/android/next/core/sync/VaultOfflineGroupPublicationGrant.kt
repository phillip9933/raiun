package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupPublicationReservation
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlin.coroutines.CoroutineContext

/** Only in-memory grants run inside the final revocation/Room critical sections. */
internal class VaultOfflineGroupPublicationGrant(
    private val identity: VaultIdentity,
    private val coroutine: CoroutineContext,
    private val livePermit: () -> Boolean,
) {
    val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
    val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)

    fun permitted(): Boolean = coroutine.isActive && livePermit() && unchanged() && !blocked()

    private fun unchanged(): Boolean =
        accountGeneration == VaultOfflineRevocations.accountGeneration(identity.accountId) &&
            identityGeneration == VaultOfflineRevocations.identityGeneration(identity)

    private fun blocked(): Boolean =
        VaultOfflineRevocations.accountBlocked(identity.accountId) ||
            VaultOfflineRevocations.identityBlocked(identity)

    fun checkActive() {
        coroutine.ensureActive()
        if (!permitted()) throw OpenCloudException(OpenCloudError.AccessDenied)
    }
}

internal suspend fun requireCurrentGroup(
    groups: VaultOfflineGroups,
    expected: VaultGroupLease,
    owner: VaultGroupOwner,
) {
    if (!groups.isCurrentOwner(owner)) throw OpenCloudException(OpenCloudError.AuthenticationRequired)
    if (!groups.isCurrent(expected)) throw OpenCloudException(OpenCloudError.SourceChanged)
}

internal fun requireGroupReservation(value: VaultGroupPublicationReservation?): VaultGroupPublicationReservation =
    value ?: throw OpenCloudException(OpenCloudError.SourceChanged)

internal suspend fun commitGroup(
    groups: VaultOfflineGroups,
    reservation: VaultGroupPublicationReservation,
    permitted: () -> Boolean,
) {
    if (!groups.commitPublication(reservation, permitted, System.currentTimeMillis())) {
        throw OpenCloudException(OpenCloudError.SourceChanged)
    }
}
