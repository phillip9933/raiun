package eu.opencloud.android.next.core.database

import androidx.room.withTransaction

internal suspend fun FileBrowserDatabase.reserveOfflineGroupPublication(
    expected: VaultGroupLease,
    publication: VaultGroupPublication,
    permit: () -> Boolean,
): VaultGroupPublicationReservation? =
    withTransaction {
        validatePublication(publication)
        val groups = VaultOfflineGroups(this@reserveOfflineGroupPublication)
        val dao = vaultOfflineGroupDao()
        if (!groups.current(expected) || expected.parent == null || expected.group.state != "AWAITING_UNLOCK"
        ) {
            return@withTransaction null
        }
        if (expected.group.pendingPublicationId != null ||
            !matchesPublication(expected.group, publication) ||
            dao.publication(publication.publicationId) != null
        ) {
            return@withTransaction null
        }
        val counts = dao.counts(expected.group.id)
        if (counts.total != publication.memberCount || counts.incomplete != 0L) return@withTransaction null
        if (counts.files != expected.group.sealedFileCount ||
            counts.bytes != expected.group.sealedCiphertextBytes ||
            !permit()
        ) {
            return@withTransaction null
        }
        val group =
            expected.group.copy(
                pendingPublicationId = publication.publicationId,
                revision = Math.addExact(expected.group.revision, 1),
            )
        val receipt =
            VaultOfflineGroupPublicationEntity(
                publicationId = publication.publicationId,
                groupId = publication.groupId,
                accountId = publication.owner.accountId,
                accountIncarnation = publication.owner.incarnation,
                identityDigest = publication.identityDigest,
                descriptorDigest = publication.descriptorDigest,
                sealedPlanDigest = publication.planDigest,
                sealedMemberCount = publication.memberCount,
                baseOfflineRootDigest = publication.baseRootDigest,
                nextOfflineRootDigest = publication.nextRootDigest,
                reservedGroupRevision = group.revision,
                createdAtEpochMillis = System.currentTimeMillis(),
                updatedAtEpochMillis = System.currentTimeMillis(),
            )
        dao.insertPublication(receipt)
        dao.updateGroup(group)
        VaultGroupPublicationReservation(expected.copy(group = group), publication, receipt)
    }

internal suspend fun FileBrowserDatabase.commitOfflineGroupPublication(
    reservation: VaultGroupPublicationReservation,
    permit: () -> Boolean,
    now: Long,
): Boolean =
    withTransaction {
        val groups = VaultOfflineGroups(this@commitOfflineGroupPublication)
        val expected = reservation.lease
        val exact = reservation.publication
        val receipt = vaultOfflineGroupDao().publication(exact.publicationId)
        if (receipt != reservation.receipt || receipt?.state != "PREPARED") return@withTransaction false
        if (!matchesReceipt(receipt, exact) || receipt.reservedGroupRevision != expected.group.revision) {
            return@withTransaction false
        }
        if (!groups.current(expected) || expected.parent == null || expected.group.state != "AWAITING_UNLOCK"
        ) {
            return@withTransaction false
        }
        if (
            expected.group.pendingPublicationId != exact.publicationId || !matchesPublication(expected.group, exact)
        ) {
            return@withTransaction false
        }
        if (!permit()) return@withTransaction false
        vaultOfflineGroupDao().updatePublication(receipt.copy(state = "COMMITTED", updatedAtEpochMillis = now))
        groups.transition(expected, "SUCCEEDED", now)
        true
    }

internal suspend fun FileBrowserDatabase.offlineGroupPublicationDecision(
    exact: VaultGroupPublication,
): VaultGroupPublicationDecision =
    withTransaction {
        val groups = VaultOfflineGroups(this@offlineGroupPublicationDecision)
        if (!groups.isOwner(exact.owner)) return@withTransaction VaultGroupPublicationDecision.REVOKED
        val receipt = vaultOfflineGroupDao().publication(exact.publicationId)
        when {
            receipt == null || !matchesReceipt(receipt, exact) -> VaultGroupPublicationDecision.UNKNOWN
            receipt.state == "COMMITTED" -> VaultGroupPublicationDecision.ACCEPTED
            receipt.state in setOf("PREPARED", "ROLLED_BACK") -> VaultGroupPublicationDecision.REJECTED
            else -> VaultGroupPublicationDecision.UNKNOWN
        }
    }

/** Caller has durably removed the journal after retaining/restoring the exact root under publication locks. */
internal suspend fun FileBrowserDatabase.acknowledgeOfflineGroupJournal(
    exact: VaultGroupPublication,
    retainedNext: Boolean,
): Boolean =
    withTransaction {
        val groups = VaultOfflineGroups(this@acknowledgeOfflineGroupJournal)
        if (!groups.isOwner(exact.owner)) return@withTransaction false
        val dao = vaultOfflineGroupDao()
        val receipt = dao.publication(exact.publicationId) ?: return@withTransaction false
        val validState =
            if (retainedNext) receipt.state == "COMMITTED" else receipt.state in setOf("PREPARED", "ROLLED_BACK")
        if (!matchesReceipt(receipt, exact) || !validState) return@withTransaction false
        dao.updatePublication(
            receipt.copy(
                state = if (retainedNext) "COMMITTED" else "ROLLED_BACK",
                journalResolved = true,
                updatedAtEpochMillis = System.currentTimeMillis(),
            ),
        )
        val group = dao.group(exact.groupId)
        if (group?.pendingPublicationId == exact.publicationId) {
            dao.updateGroup(group.copy(pendingPublicationId = null, revision = Math.addExact(group.revision, 1)))
        }
        true
    }

private fun validatePublication(value: VaultGroupPublication) {
    listOf(value.publicationId, value.groupId).forEach(::requireUuid)
    listOf(value.identityDigest, value.descriptorDigest, value.planDigest, value.baseRootDigest, value.nextRootDigest)
        .forEach(::requireDigest)
    require(value.memberCount >= 1)
}

private fun matchesPublication(
    group: VaultOfflineGroupEntity,
    exact: VaultGroupPublication,
): Boolean =
    group.id == exact.groupId &&
        group.owner() == exact.owner &&
        group.identityDigest == exact.identityDigest &&
        group.descriptorDigest == exact.descriptorDigest &&
        group.sealedPlanDigest == exact.planDigest &&
        group.sealedMemberCount == exact.memberCount &&
        group.baseOfflineRootDigest == exact.baseRootDigest

private fun matchesReceipt(
    receipt: VaultOfflineGroupPublicationEntity,
    exact: VaultGroupPublication,
): Boolean =
    receipt.publicationId == exact.publicationId &&
        receipt.groupId == exact.groupId &&
        receipt.accountId == exact.owner.accountId &&
        receipt.accountIncarnation == exact.owner.incarnation &&
        receipt.identityDigest == exact.identityDigest &&
        receipt.descriptorDigest == exact.descriptorDigest &&
        receipt.sealedPlanDigest == exact.planDigest &&
        receipt.sealedMemberCount == exact.memberCount &&
        receipt.baseOfflineRootDigest == exact.baseRootDigest &&
        receipt.nextOfflineRootDigest == exact.nextRootDigest
