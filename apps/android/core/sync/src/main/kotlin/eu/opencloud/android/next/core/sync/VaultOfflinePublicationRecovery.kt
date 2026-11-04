package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Caller holds the canonical identity lock; local, transfer and group receipts retain distinct authority. */
@Suppress("LongParameterList") // Recovery receives only the exact identity and existing authority callbacks.
internal suspend fun recoverOfflinePublication(
    ownership: VaultOfflineOwnership,
    identity: VaultIdentity,
    location: VaultLocation,
    groupAuthority: VaultOfflineGroups?,
    requireAccount: suspend () -> Unit,
    publicationAccepted: suspend (String, VaultIdentity) -> Boolean,
) {
    val directory = ownership.vaultDirectory(identity)
    val journal = VaultOfflinePublicationJournal.read(directory) ?: return
    val captured = decodeLocation(journal.locationDescriptor)
    requireLocation(identity, captured)
    if (captured.rootWebDavUrl != location.rootWebDavUrl || captured.vaultPath != location.vaultPath) {
        throw OpenCloudException(OpenCloudError.DownloadIntegrity)
    }
    if (journal.groupPublication != null) {
        recoverOfflineGroupJournal(ownership, identity, journal, groupAuthority)
        return
    }
    val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
    val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
    withContext(NonCancellable) {
        requireAccount()
        val accepted = journal.localCommitted ?: publicationAccepted(journal.publicationId, identity)
        requireAccount()
        VaultOfflineRevocations.runIfUnchanged(identity, accountGeneration, identityGeneration) {
            val persistentlyRevoked =
                ownership.accountRevoked(identity.accountId) || ownership.identityRevoked(identity)
            val sessionRevoked =
                VaultOfflineRevocations.accountBlocked(identity.accountId) ||
                    VaultOfflineRevocations.identityBlocked(identity)
            if (persistentlyRevoked || sessionRevoked) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            if (!accepted) journal.restore(directory, ownership.durability)
            journal.finish(directory, accepted, ownership.durability)
        }
    }
}
