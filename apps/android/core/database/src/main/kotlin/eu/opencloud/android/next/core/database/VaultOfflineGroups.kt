package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import kotlinx.coroutines.flow.Flow
import java.io.IOException
import java.util.UUID

fun FileBrowserStore.vaultOfflineGroups(): VaultOfflineGroups = VaultOfflineGroups(database)

/** Durable scheduling ownership. Transport hints never authenticate the sealed plan or offline contents. */
class VaultOfflineGroups(
    internal val database: FileBrowserDatabase,
) {
    internal val dao get() = database.vaultOfflineGroupDao()

    fun observeAwaiting(
        accountId: String,
        driveId: String,
        remoteVaultId: String,
    ): Flow<String?> = dao.observeAwaiting(accountId, driveId, remoteVaultId)

    suspend fun captureOwner(accountId: String): VaultGroupOwner? =
        database.withTransaction {
            val account = database.accountDao().findById(accountId) ?: return@withTransaction null
            val owner = database.ensureAccountIncarnation(accountId)
            VaultGroupOwner(accountId, owner.incarnation, accountIdentityDigest(account))
        }

    suspend fun isCurrentOwner(owner: VaultGroupOwner): Boolean = database.withTransaction { isOwner(owner) }

    suspend fun isCurrent(expected: VaultGroupLease): Boolean = database.withTransaction { current(expected) }

    suspend fun hasUnresolved(
        owner: VaultGroupOwner,
        groupId: String,
    ): Boolean =
        database.withTransaction {
            if (!isOwner(owner)) return@withTransaction false
            dao.unresolvedGroup(owner.accountId, owner.incarnation, groupId)
        }

    suspend fun find(groupId: String): VaultGroupLease? =
        database.withTransaction {
            val group = dao.group(groupId) ?: return@withTransaction null
            if (!isOwner(group.owner())) return@withTransaction null
            VaultGroupLease(group, database.transferDao().findById(groupId))
        }

    suspend fun active(
        owner: VaultGroupOwner,
        driveId: String,
        remoteVaultId: String,
    ): VaultGroupLease? =
        database.withTransaction {
            if (!isOwner(owner)) return@withTransaction null
            val group = dao.active(owner.accountId, driveId, remoteVaultId) ?: return@withTransaction null
            VaultGroupLease(group, database.transferDao().findById(group.id))
        }

    suspend fun beginPreparation(
        owner: VaultGroupOwner,
        frozen: VaultGroupDescriptor,
        now: Long = System.currentTimeMillis(),
    ): VaultGroupLease? =
        database.withTransaction {
            validateDescriptor(frozen)
            if (!isOwner(owner) ||
                dao.group(frozen.groupId) != null ||
                database.transferDao().findById(frozen.groupId) != null
            ) {
                return@withTransaction null
            }
            if (
                dao.active(owner.accountId, frozen.driveId, frozen.remoteVaultId) != null ||
                dao.unresolved(owner.accountId, owner.incarnation, frozen.identityDigest)
            ) {
                return@withTransaction null
            }
            val group =
                VaultOfflineGroupEntity(
                    id = frozen.groupId,
                    accountId = owner.accountId,
                    accountIncarnation = owner.incarnation,
                    driveId = frozen.driveId,
                    remoteVaultId = frozen.remoteVaultId,
                    accountIdentityDigest = owner.accountIdentityDigest,
                    identityDigest = frozen.identityDigest,
                    descriptorId = frozen.descriptorId,
                    descriptorDigest = frozen.descriptorDigest,
                    baseOfflineRootDigest = frozen.baseOfflineRootDigest,
                    planId = frozen.planId,
                    stagingChainDigest = groupDigest("raiun-group-staging-v1", frozen.groupId),
                    createdAtEpochMillis = now,
                    updatedAtEpochMillis = now,
                )
            dao.insertGroup(group)
            VaultGroupLease(group, null)
        }

    suspend fun appendMembers(
        expected: VaultGroupLease,
        firstSequence: Long,
        members: List<VaultGroupMemberAdmission>,
        expectedChain: String,
        nextChain: String,
    ): VaultGroupLease? =
        database.withTransaction {
            require(members.size in 1..VAULT_GROUP_PAGE_SIZE)
            requireDigest(expectedChain)
            requireDigest(nextChain)
            if (!current(expected) || expected.group.state != "PREPARING" || expected.parent != null
            ) {
                return@withTransaction null
            }
            if (firstSequence != expected.group.stagedMemberCount || expectedChain != expected.group.stagingChainDigest
            ) {
                return@withTransaction null
            }
            val rows =
                members.mapIndexed { index, member ->
                    validateMember(member)
                    require(member.sequence == Math.addExact(firstSequence, index.toLong()))
                    if (member.sequence == 0L) require(member.kind == "DIRECTORY")
                    VaultOfflineGroupMemberEntity(
                        expected.group.id,
                        member.sequence,
                        member.memberId,
                        member.descriptorDigest,
                        member.kind,
                        if (member.kind == "DIRECTORY") "DOWNLOADED" else "PENDING",
                        payloadId = member.payloadId,
                    )
                }
            dao.insertMembers(rows)
            val next =
                expected.group.copy(
                    stagedMemberCount = Math.addExact(firstSequence, members.size.toLong()),
                    stagingChainDigest = nextChain,
                    revision = Math.addExact(expected.group.revision, 1),
                )
            dao.updateGroup(next)
            VaultGroupLease(next, null)
        }

    suspend fun sealAndEnqueue(
        expected: VaultGroupLease,
        seal: VaultGroupSeal,
        parent: TransferEntity,
        admissionStillPermitted: () -> Boolean,
    ): VaultGroupLease? =
        database.withTransaction {
            validateSeal(seal)
            validateParent(expected.group, parent, seal)
            if (!current(expected) || expected.group.state != "PREPARING" || expected.parent != null
            ) {
                return@withTransaction null
            }
            if (seal.planId != expected.group.planId || seal.memberCount != expected.group.stagedMemberCount
            ) {
                return@withTransaction null
            }
            val counts = dao.counts(expected.group.id)
            if (counts.total != seal.memberCount || counts.files != seal.fileCount || !admissionStillPermitted()) {
                return@withTransaction null
            }
            val group =
                expected.group.copy(
                    sealedPlanDigest = seal.digest,
                    sealedMemberCount = seal.memberCount,
                    sealedFileCount = seal.fileCount,
                    sealedCiphertextBytes = seal.ciphertextBytes,
                    state = "QUEUED",
                    revision = Math.addExact(expected.group.revision, 1),
                    updatedAtEpochMillis = parent.updatedAtEpochMillis,
                )
            database.transferDao().insert(parent)
            dao.updateGroup(group)
            VaultGroupLease(group, parent)
        }

    suspend fun memberPage(
        expected: VaultGroupLease,
        afterSequence: Long? = null,
    ): List<VaultOfflineGroupMemberEntity> =
        database.withTransaction {
            requireCurrent(expected)
            dao.members(expected.group.id, afterSequence)
        }

    suspend fun claim(
        expected: VaultGroupLease,
        workerId: String,
        now: Long,
    ): VaultGroupAttempt? =
        database.withTransaction {
            requireUuid(workerId)
            val parent = expected.parent ?: return@withTransaction null
            if (parent.workId != null && parent.workId != workerId) return@withTransaction null
            // A restarted exact WorkManager intent may retain RUNNING; a fresh attempt revokes its old CAS lease.
            if (!current(expected) || expected.group.state !in setOf("QUEUED", "RETRY", "RUNNING")) {
                return@withTransaction null
            }
            if (expected.group.pendingPublicationId != null || parent.notBeforeEpochMillis > now
            ) {
                return@withTransaction null
            }
            val attemptId = UUID.randomUUID().toString()
            val group =
                expected.group.copy(
                    state = "RUNNING",
                    attemptId = attemptId,
                    revision = Math.addExact(expected.group.revision, 1),
                    updatedAtEpochMillis = now,
                )
            val next =
                parent.copy(
                    state = "RUNNING",
                    workId = workerId,
                    attemptCount = Math.addExact(parent.attemptCount, 1),
                    updatedAtEpochMillis = now,
                )
            dao.updateGroup(group)
            database.transferDao().update(next)
            VaultGroupAttempt(VaultGroupLease(group, next), attemptId)
        }

    suspend fun checkpoint(
        attempt: VaultGroupAttempt,
        expectedMember: VaultOfflineGroupMemberEntity,
        checkpoint: VaultGroupCheckpoint,
    ): VaultGroupCheckpointResult? =
        database.withTransaction {
            validateCheckpoint(checkpoint)
            val expected = attempt.lease
            val parent = expected.parent ?: return@withTransaction null
            if (!currentAttempt(attempt) || expectedMember.groupId != expected.group.id) return@withTransaction null
            if (expectedMember.kind != "FILE" ||
                dao.member(expected.group.id, expectedMember.sequence) != expectedMember
            ) {
                return@withTransaction null
            }
            val bytes =
                Math.addExact(
                    parent.bytesTransferred,
                    Math.subtractExact(checkpoint.checkpointBytes, expectedMember.checkpointBytes),
                )
            require(bytes in 0..parent.bytesTotal)
            val member =
                expectedMember.copy(
                    state = checkpoint.state,
                    revision = Math.addExact(expectedMember.revision, 1),
                    attemptId = attempt.attemptId,
                    checkpointBytes = checkpoint.checkpointBytes,
                    ciphertextDigest = checkpoint.ciphertextDigest,
                    errorCode = checkpoint.errorCode,
                )
            val updatedParent = parent.copy(bytesTransferred = bytes)
            dao.updateMember(member)
            database.transferDao().update(updatedParent)
            VaultGroupCheckpointResult(attempt.copy(lease = expected.copy(parent = updatedParent)), member)
        }

    suspend fun awaitUnlock(
        attempt: VaultGroupAttempt,
        now: Long,
    ): VaultGroupLease? =
        database.withTransaction {
            if (!currentAttempt(attempt)) return@withTransaction null
            val counts = dao.counts(attempt.lease.group.id)
            val group = attempt.lease.group
            if (counts.total != group.sealedMemberCount || counts.files != group.sealedFileCount) {
                return@withTransaction null
            }
            if (counts.incomplete != 0L || counts.bytes != group.sealedCiphertextBytes
            ) {
                return@withTransaction null
            }
            transition(attempt.lease, "AWAITING_UNLOCK", now)
        }

    suspend fun cancel(
        expected: VaultGroupLease,
        now: Long,
    ): VaultGroupLease? =
        database.withTransaction {
            if (!current(expected) || expected.group.state in setOf("SUCCEEDED", "CANCELLED")) {
                return@withTransaction null
            }
            // Clear-all includes failed groups; preserve the reason that requires a fresh offline capture.
            transition(expected, "CANCELLED", now, errorCode = expected.group.errorCode)
        }

    suspend fun fail(
        expected: VaultGroupLease,
        errorCode: String,
        now: Long,
        message: String? = null,
    ): VaultGroupLease? =
        database.withTransaction {
            requireErrorCode(errorCode)
            if (!current(expected) || expected.group.state in TERMINAL_GROUP_STATES) return@withTransaction null
            transition(expected, "FAILED", now, errorCode, message)
        }

    suspend fun deferRetry(
        expected: VaultGroupLease,
        errorCode: String,
        notBeforeEpochMillis: Long,
        now: Long,
        message: String? = null,
    ): VaultGroupLease? =
        database.withTransaction {
            requireErrorCode(errorCode)
            require(notBeforeEpochMillis >= 0)
            if (!current(expected) || expected.group.state != "RUNNING") return@withTransaction null
            val parent = expected.parent ?: return@withTransaction null
            val next = transition(expected, "RETRY", now, errorCode, message)
            val deferred =
                requireNotNull(next.parent).copy(
                    workId = parent.workId,
                    notBeforeEpochMillis = notBeforeEpochMillis,
                )
            database.transferDao().update(deferred)
            next.copy(parent = deferred)
        }

    suspend fun retry(
        expected: VaultGroupLease,
        workerId: String,
        now: Long,
        bulkScope: TransferBulkScope? = null,
    ): VaultGroupLease? = database.retryOfflineGroup(expected, workerId, now, bulkScope)

    suspend fun groupPage(
        owner: VaultGroupOwner,
        afterGroupId: String? = null,
    ): List<VaultOfflineGroupEntity> =
        database.withTransaction {
            if (!isOwner(owner)) throw IOException("The encrypted offline account changed.")
            dao.groups(owner.accountId, owner.incarnation, afterGroupId)
        }

    suspend fun unresolvedPublicationPage(
        owner: VaultGroupOwner,
        afterPublicationId: String? = null,
    ): List<VaultOfflineGroupPublicationEntity> =
        database.withTransaction {
            if (!isOwner(owner)) throw IOException("The encrypted offline account changed.")
            dao.publications(owner.accountId, owner.incarnation, afterPublicationId)
        }

    suspend fun reservePublication(
        expected: VaultGroupLease,
        publication: VaultGroupPublication,
        publicationStillPermitted: () -> Boolean,
    ): VaultGroupPublicationReservation? =
        database.reserveOfflineGroupPublication(expected, publication, publicationStillPermitted)

    suspend fun commitPublication(
        reservation: VaultGroupPublicationReservation,
        publicationStillPermitted: () -> Boolean,
        now: Long,
    ): Boolean = database.commitOfflineGroupPublication(reservation, publicationStillPermitted, now)

    suspend fun publicationDecision(exact: VaultGroupPublication): VaultGroupPublicationDecision =
        database.offlineGroupPublicationDecision(exact)

    suspend fun acknowledgeJournalResolved(
        exact: VaultGroupPublication,
        retainedNext: Boolean,
    ): Boolean = database.acknowledgeOfflineGroupJournal(exact, retainedNext)

    internal suspend fun isOwner(owner: VaultGroupOwner): Boolean {
        val account = database.accountDao().findById(owner.accountId) ?: return false
        return dao.owner(owner.accountId)?.incarnation == owner.incarnation &&
            accountIdentityDigest(account) == owner.accountIdentityDigest
    }

    internal suspend fun current(expected: VaultGroupLease): Boolean =
        isOwner(expected.group.owner()) &&
            dao.group(expected.group.id) == expected.group &&
            database.transferDao().findById(expected.group.id) == expected.parent &&
            (expected.parent == null || parentMatchesGroup(expected.group, expected.parent))

    internal suspend fun currentAttempt(attempt: VaultGroupAttempt): Boolean =
        current(attempt.lease) &&
            attempt.lease.group.state == "RUNNING" &&
            attempt.lease.group.attemptId == attempt.attemptId

    internal suspend fun requireCurrent(expected: VaultGroupLease) {
        if (!current(expected)) throw IOException("The encrypted offline group changed.")
    }

    internal suspend fun transition(
        expected: VaultGroupLease,
        state: String,
        now: Long,
        errorCode: String? = null,
        message: String? = null,
    ): VaultGroupLease {
        val terminal = state in TERMINAL_GROUP_STATES
        val group =
            expected.group.copy(
                state = state,
                revision = Math.addExact(expected.group.revision, 1),
                attemptId = null,
                activeSlot = if (terminal) null else 1,
                errorCode = errorCode,
                updatedAtEpochMillis = now,
            )
        val parent =
            expected.parent?.copy(
                state = state,
                workId = null,
                verificationPending = state == "AWAITING_UNLOCK",
                error = message,
                errorCode = errorCode,
                updatedAtEpochMillis = now,
            )
        dao.updateGroup(group)
        if (parent != null) database.transferDao().update(parent)
        return VaultGroupLease(group, parent)
    }
}

internal val TERMINAL_GROUP_STATES = setOf("SUCCEEDED", "FAILED", "CANCELLED")

internal fun VaultOfflineGroupEntity.owner() = VaultGroupOwner(accountId, accountIncarnation, accountIdentityDigest)

internal fun parentMatchesGroup(
    group: VaultOfflineGroupEntity,
    parent: TransferEntity,
): Boolean =
    parent.id == group.id &&
        parent.accountId == group.accountId &&
        parent.spaceId == group.driveId &&
        parent.locationKind == VAULT_GROUP_LOCATION_KIND &&
        parent.direction == "DOWNLOAD" &&
        parent.sourceUri == "vault-offline-group:${group.remoteVaultId}" &&
        parent.state == group.state &&
        parent.bytesTotal == group.sealedCiphertextBytes &&
        parent.offlinePin &&
        !parent.overwrite &&
        !parent.deleteSourceAfterSuccess

internal fun requireDigest(value: String) = require(value.matches(Regex("[a-f0-9]{64}")))

internal fun requireUuid(value: String) = require(UUID.fromString(value).toString() == value)

internal fun requireErrorCode(value: String) = require(value.matches(Regex("[A-Z][A-Z0-9_]{0,63}")))

private fun validateDescriptor(value: VaultGroupDescriptor) {
    listOf(value.groupId, value.descriptorId, value.planId).forEach(::requireUuid)
    listOf(value.identityDigest, value.descriptorDigest, value.baseOfflineRootDigest).forEach(::requireDigest)
    require(value.driveId.isNotBlank() && value.remoteVaultId.isNotBlank())
}

private fun validateMember(value: VaultGroupMemberAdmission) {
    require(value.sequence >= 0)
    requireUuid(value.memberId)
    requireDigest(value.descriptorDigest)
    require(value.kind in setOf("DIRECTORY", "FILE"))
    if (value.kind == "FILE") requireUuid(requireNotNull(value.payloadId)) else require(value.payloadId == null)
}

private fun validateSeal(value: VaultGroupSeal) {
    requireUuid(value.planId)
    requireDigest(value.digest)
    require(value.memberCount >= 1 && value.fileCount in 0..value.memberCount && value.ciphertextBytes >= 0)
    val minimumBytes = Math.multiplyExact(value.fileCount, 32)
    require(if (value.fileCount == 0L) value.ciphertextBytes == 0L else value.ciphertextBytes >= minimumBytes)
}

private fun validateParent(
    group: VaultOfflineGroupEntity,
    parent: TransferEntity,
    seal: VaultGroupSeal,
) {
    require(parentMatchesGroup(group.copy(state = "QUEUED", sealedCiphertextBytes = seal.ciphertextBytes), parent))
    require(parent.resourceId == null && parent.bytesTransferred == 0L && !parent.verificationPending)
    require(parent.tusUrl == null && parent.tusOffset == 0L && parent.expectedETag == null)
}

private fun validateCheckpoint(value: VaultGroupCheckpoint) {
    require(value.state in setOf("PENDING", "RUNNING", "DOWNLOADED", "FAILED"))
    require(value.checkpointBytes >= 0)
    value.ciphertextDigest?.let(::requireDigest)
    value.errorCode?.let(::requireErrorCode)
    if (value.state == "DOWNLOADED") require(value.checkpointBytes >= 32 && value.ciphertextDigest != null)
}
