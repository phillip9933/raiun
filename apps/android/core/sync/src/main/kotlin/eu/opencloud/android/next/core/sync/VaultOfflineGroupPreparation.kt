package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VAULT_GROUP_LOCATION_KIND
import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupMemberAdmission
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.UUID

/** Capture the entire subtree before accepting one durable, independently cancellable transfer. */
suspend fun VaultSession.enqueueBackgroundOfflineGroup(
    context: Context,
    path: String,
    selectedEntry: VaultFolder? = null,
): String =
    withContext(Dispatchers.IO) {
        val store = FileBrowserStore(FileBrowserDatabase.create(context))
        val groups = store.vaultOfflineGroups()
        val owner = groups.captureOwner(identity.accountId) ?: groupAccessDenied()
        val accountLease = AccountSessions.get(context).beginLease(identity.accountId)
        val coroutine = currentCoroutineContext()
        val permit = {
            coroutine.ensureActive()
            accountLease()
        }
        val plans = VaultOfflineGroupPlanStore(context)
        val offline = VaultOfflineStore(context)
        val accepted =
            withOfflineGroupSource(context, path, selectedEntry, permit) { source ->
                val base = source.withMaterial { offline.ensureGroupAnchor(identity, location, it, permit) }
                val frozen =
                    VaultOfflineGroupContext(
                        UUID.randomUUID().toString(),
                        owner,
                        identity,
                        location.copy(title = ""),
                        source.selected.relativePath,
                        source.rootProofDigest,
                        base,
                    )
                prepareVaultOfflineGroup(context, source, frozen, groups, plans, permit)
            }
        // Admission is durable before scheduling; startup can recover an interrupted scheduler delivery.
        TransferManager(context, store).scheduleVaultDownload(accepted)
        accepted.id
    }

@Suppress("LongParameterList") // Source, frozen claim, stores and live permit must share admission ownership.
internal suspend fun prepareVaultOfflineGroup(
    context: Context,
    source: VaultOfflineGroupSource,
    frozen: VaultOfflineGroupContext,
    groups: VaultOfflineGroups,
    plans: VaultOfflineGroupPlanStore,
    permit: () -> Boolean,
): TransferEntity {
    val sameIdentity = frozen.identity == source.identity && frozen.location == source.location.copy(title = "")
    val sameRoot =
        frozen.selectedEncryptedRoot == source.selected.relativePath &&
            frozen.rootProofDigest == source.rootProofDigest
    if (!sameIdentity || !sameRoot) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    // Register live private preparation before Room exposes PREPARING to startup reconciliation.
    val building = plans.begin(frozen) { source.checkActive() }
    return try {
        val claim =
            groups.beginPreparation(frozen.owner, frozen.descriptor())
                ?: throw OpenCloudException(OpenCloudError.OfflineGroupBusy)
        val admission = GroupPreparationAdmission(groups, claim)
        admission.append(building.appendDirectory(source.selected).admission())
        captureGroupTree(context, source, building, admission)
        admission.flush()
        source.requireCurrent()
        val seal = source.withMaterial { building.seal(it) { source.checkActive() } }
        source.requireCurrent()
        val now = System.currentTimeMillis()
        val parent =
            TransferEntity(
                id = frozen.groupId,
                accountId = frozen.identity.accountId,
                spaceId = frozen.identity.driveId,
                resourceId = null,
                direction = "DOWNLOAD",
                sourceUri = "vault-offline-group:${frozen.identity.remoteVaultId}",
                destinationPath = frozen.selectedEncryptedRoot,
                displayName = context.getString(R.string.encrypted_offline_download),
                mimeType = "application/octet-stream",
                bytesTotal = seal.ciphertextBytes,
                offlinePin = true,
                locationKind = VAULT_GROUP_LOCATION_KIND,
                createdAtEpochMillis = now,
                updatedAtEpochMillis = now,
            )
        groups
            .sealAndEnqueue(admission.current, seal, parent) {
                source.checkActive()
                permit()
            }?.parent ?: groupAccessDenied()
    } finally {
        withContext(NonCancellable) {
            try {
                val durable = groups.find(frozen.groupId)
                val retained = building.finishPrepared { durable?.parent != null }
                if (!retained && durable != null && durable.parent == null) {
                    groups.cancel(durable, System.currentTimeMillis())
                }
            } finally {
                // A failed database ownership read must still release our writer and live registry entry.
                // Sealed close preserves bytes when durable admission could have succeeded.
                building.close()
            }
        }
    }
}

private suspend fun captureGroupTree(
    context: Context,
    source: VaultOfflineGroupSource,
    building: VaultOfflineGroupPlanStore.Preparation,
    admission: GroupPreparationAdmission,
) {
    BackupDirectoryQueue(context).use { frontier ->
        frontier.add(source.selected.id, source.selected.relativePath)
        while (true) {
            source.requireCurrent()
            val (id, encryptedPath) = frontier.take() ?: break
            val directory =
                if (encryptedPath == source.selected.relativePath) {
                    source.selected
                } else {
                    source.rawEntry(
                        BoundaryEntry(id, encryptedPath, encryptedPath.substringAfterLast('/'), true, 0, null),
                    )
                }
            captureGroupDirectory(source, building, admission, frontier, directory)
        }
    }
}

private suspend fun captureGroupDirectory(
    source: VaultOfflineGroupSource,
    building: VaultOfflineGroupPlanStore.Preparation,
    admission: GroupPreparationAdmission,
    frontier: BackupDirectoryQueue,
    directory: eu.opencloud.android.next.core.network.VaultDavEntry,
) {
    source.openDirectory(directory).use { snapshot ->
        var after = 0L
        while (after < snapshot.totalCount) {
            val page = snapshot.page(after)
            if (page.isEmpty()) throw OpenCloudException(OpenCloudError.InvalidResponse)
            for (child in page) captureGroupMember(source, building, admission, frontier, child)
            after = Math.addExact(after, page.size.toLong())
        }
    }
}

private suspend fun captureGroupMember(
    source: VaultOfflineGroupSource,
    building: VaultOfflineGroupPlanStore.Preparation,
    admission: GroupPreparationAdmission,
    frontier: BackupDirectoryQueue,
    child: BoundaryEntry,
) {
    source.checkActive()
    val raw = source.rawEntry(child)
    val member = if (raw.isFolder) building.appendDirectory(raw) else building.appendFile(raw)
    admission.append(member.admission())
    if (raw.isFolder) frontier.add(raw.id, raw.relativePath)
}

private class GroupPreparationAdmission(
    private val groups: VaultOfflineGroups,
    var current: VaultGroupLease,
) {
    private val pending = ArrayList<VaultGroupMemberAdmission>(128)

    suspend fun append(member: VaultGroupMemberAdmission) {
        pending.add(member)
        if (pending.size == 128) flush()
    }

    suspend fun flush() {
        if (pending.isEmpty()) return
        val previous = current.group.stagingChainDigest
        val hash = MessageDigest.getInstance("SHA-256")
        hash.update(previous.toByteArray(Charsets.US_ASCII))
        pending.forEach { hash.update(it.descriptorDigest.toByteArray(Charsets.US_ASCII)) }
        val next = hash.digest().joinToString("") { "%02x".format(it) }
        current = groups.appendMembers(current, pending.first().sequence, pending.toList(), previous, next)
            ?: groupAccessDenied()
        pending.clear()
    }
}

private fun groupAccessDenied(): Nothing = throw OpenCloudException(OpenCloudError.AccessDenied)
