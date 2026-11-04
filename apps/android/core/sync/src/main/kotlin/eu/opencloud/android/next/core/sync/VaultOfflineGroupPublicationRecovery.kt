package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.VaultGroupPublicationDecision
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

internal fun offlineMetadataDigest(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/** Caller owns account-publication/identity locks as appropriate; no keys are used in recovery. */
internal suspend fun recoverOfflineGroupJournal(
    ownership: VaultOfflineOwnership,
    identity: VaultIdentity,
    journal: VaultOfflinePublicationJournal,
    groups: VaultOfflineGroups?,
): Boolean =
    withContext(NonCancellable) {
        val exact = requireNotNull(journal.groupPublication)
        if (exact.owner.accountId != identity.accountId ||
            exact.identityDigest != offlineMetadataDigest(identityBytes(identity))
        ) {
            throw OpenCloudException(OpenCloudError.DownloadIntegrity)
        }
        val authority = groups ?: throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        val accepted =
            when (authority.publicationDecision(exact)) {
                VaultGroupPublicationDecision.ACCEPTED -> true
                VaultGroupPublicationDecision.REJECTED -> false
                VaultGroupPublicationDecision.REVOKED -> throw OpenCloudException(OpenCloudError.AuthenticationRequired)
                VaultGroupPublicationDecision.UNKNOWN -> throw OpenCloudException(
                    OpenCloudError.LocalStorageWriteFailed,
                )
            }
        val directory = ownership.vaultDirectory(identity)
        VaultOfflineRevocations.runIfUnchanged(identity, accountGeneration, identityGeneration) {
            requireOfflineGroupNotForgotten(ownership, identity)
            if (!accepted) journal.restore(directory, ownership.durability)
            journal.finish(directory, accepted, ownership.durability)
        }
        if (!authority.acknowledgeJournalResolved(exact, accepted)) {
            throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
        }
        accepted
    }

internal fun requireOfflineGroupNotForgotten(
    ownership: VaultOfflineOwnership,
    identity: VaultIdentity,
) {
    val revoked =
        VaultOfflineRevocations.accountBlocked(identity.accountId) ||
            VaultOfflineRevocations.identityBlocked(identity)
    if (revoked || ownership.accountRevoked(identity.accountId) || ownership.identityRevoked(identity)) {
        throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
    }
}

/** An independent receipt can outlive transfer history or a crash before the FS journal was written. */
internal suspend fun resolveOfflineGroupWithoutJournal(
    ownership: VaultOfflineOwnership,
    identity: VaultIdentity,
    exact: VaultGroupPublication,
    groups: VaultOfflineGroups,
): VaultGroupPublicationDecision =
    withContext(NonCancellable) {
        if (exact.owner.accountId != identity.accountId ||
            exact.identityDigest != offlineMetadataDigest(identityBytes(identity))
        ) {
            return@withContext VaultGroupPublicationDecision.UNKNOWN
        }
        val decision = groups.publicationDecision(exact)
        if (decision in
            setOf(VaultGroupPublicationDecision.UNKNOWN, VaultGroupPublicationDecision.REVOKED)
        ) {
            return@withContext decision
        }
        val directory = ownership.vaultDirectory(identity)
        if (VaultOfflinePublicationJournal.read(directory) !=
            null
        ) {
            return@withContext VaultGroupPublicationDecision.UNKNOWN
        }
        requireOfflineGroupNotForgotten(ownership, identity)
        val root = File(directory, "manifest.enc")
        if (!root.isFile && !File(root.path + ".bak").isFile) return@withContext VaultGroupPublicationDecision.UNKNOWN
        val digest = offlineMetadataDigest(readOfflineMetadata(root, 16 * 1024 * 1024 + 32, ownership.durability))
        val retainedNext =
            when {
                decision == VaultGroupPublicationDecision.ACCEPTED && digest == exact.nextRootDigest -> true
                decision == VaultGroupPublicationDecision.REJECTED && digest == exact.baseRootDigest -> false
                else -> return@withContext VaultGroupPublicationDecision.UNKNOWN
            }
        if (!groups.acknowledgeJournalResolved(
                exact,
                retainedNext,
            )
        ) {
            return@withContext VaultGroupPublicationDecision.UNKNOWN
        }
        decision
    }
