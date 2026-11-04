package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.IOException
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupsTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var groups: VaultOfflineGroups
    private lateinit var store: FileBrowserStore
    private val account = AccountEntity("a", "https://example.test", "u", "U", "BASIC", false)

    @Before fun setup() =
        runBlocking {
            database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            store = FileBrowserStore(database)
            groups = store.vaultOfflineGroups()
            database.accountDao().upsert(account)
        }

    @After fun close() = database.close()

    @Test fun preparingGroupExcludesConcurrentScopeAndDoesNotPublishParentBeforeSealing() =
        runBlocking {
            val owner = requireNotNull(groups.captureOwner("a"))
            val first = requireNotNull(groups.beginPreparation(owner, descriptor()))
            assertNull(store.transfer(first.group.id))
            assertNull(groups.beginPreparation(owner, descriptor()))
            assertEquals(first, groups.active(owner, "drive", "vault"))
            val unpreparedSeal = VaultGroupSeal(first.group.planId, digest('b'), 1, 0, 0)
            assertNull(groups.sealAndEnqueue(first, unpreparedSeal, parent(first, 0)) { true })
            val cancelled = requireNotNull(groups.cancel(first, 2))
            assertEquals("CANCELLED", cancelled.group.state)
            assertNull(cancelled.group.activeSlot)
            assertTrue(groups.beginPreparation(owner, descriptor()) != null)
        }

    @Test fun fixedSequenceMembershipPagesAreBoundedAndStalePreparationCannotAppendOrSeal() =
        runBlocking {
            val owner = requireNotNull(groups.captureOwner("a"))
            val first = requireNotNull(groups.beginPreparation(owner, descriptor()))
            val all = admissions(390)
            var lease = first
            for (batch in all.chunked(128)) {
                lease =
                    requireNotNull(
                        groups.appendMembers(
                            lease,
                            batch.first().sequence,
                            batch,
                            lease.group.stagingChainDigest,
                            digest('c'),
                        ),
                    )
            }
            assertNull(groups.appendMembers(first, 0, all.take(1), first.group.stagingChainDigest, digest('d')))
            val seen = mutableListOf<VaultOfflineGroupMemberEntity>()
            var after: Long? = null
            while (true) {
                val page = groups.memberPage(lease, after)
                if (page.isEmpty()) break
                assertTrue(page.size <= 128)
                seen += page
                after = page.last().sequence
            }
            assertEquals((0L until 390L).toList(), seen.map { it.sequence })
            assertEquals(all.map { it.memberId }, seen.map { it.memberId })
            val seal = VaultGroupSeal(lease.group.planId, digest('e'), 390, 389, 389L * 32)
            assertNull(groups.sealAndEnqueue(lease, seal, parent(lease, seal.ciphertextBytes)) { false })
            assertNull(store.transfer(lease.group.id))
            val queued =
                requireNotNull(groups.sealAndEnqueue(lease, seal, parent(lease, seal.ciphertextBytes)) { true })
            assertEquals("QUEUED", queued.parent?.state)
            assertEquals(seal.digest, queued.group.sealedPlanDigest)
            assertFalse(groups.isCurrent(lease))
        }

    @Test fun directoryOnlyGroupHasZeroBytesAndStillRequiresWorkerAndPublicationBarrier() =
        runBlocking {
            val queued = queued(0)
            assertEquals(0L, queued.parent?.bytesTotal)
            assertNull(groups.reservePublication(queued, publication(queued)) { true })
            val attempt = requireNotNull(groups.claim(queued, uuid(), 2))
            val awaiting = requireNotNull(groups.awaitUnlock(attempt, 3))
            assertTrue(awaiting.parent!!.verificationPending)
            val exact = publication(awaiting)
            val reservation = requireNotNull(groups.reservePublication(awaiting, exact) { true })
            assertEquals(VaultGroupPublicationDecision.REJECTED, groups.publicationDecision(exact))
            assertTrue(groups.commitPublication(reservation, { true }, 4))
            assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(exact))
        }

    @Test fun progressUsesExactMemberAndParentCasAndDoesNotTurnTransportIntoSuccess() =
        runBlocking {
            val queued = queued(1)
            val attempt = requireNotNull(groups.claim(queued, uuid(), 2))
            val file = groups.memberPage(attempt.lease).single { it.kind == "FILE" }
            assertNull(groups.awaitUnlock(attempt, 3))
            val partial = requireNotNull(groups.checkpoint(attempt, file, VaultGroupCheckpoint("RUNNING", 16)))
            assertEquals(
                16L,
                partial.attempt.lease.parent
                    ?.bytesTransferred,
            )
            assertNull(groups.checkpoint(attempt, file, VaultGroupCheckpoint("DOWNLOADED", 32, digest('f'))))
            val completed =
                requireNotNull(
                    groups.checkpoint(
                        partial.attempt,
                        partial.member,
                        VaultGroupCheckpoint("DOWNLOADED", 32, digest('f')),
                    ),
                )
            val awaiting = requireNotNull(groups.awaitUnlock(completed.attempt, 4))
            assertEquals("AWAITING_UNLOCK", awaiting.group.state)
            assertEquals("AWAITING_UNLOCK", awaiting.parent?.state)
            assertNull(groups.checkpoint(completed.attempt, completed.member, VaultGroupCheckpoint("RUNNING", 1)))
            assertEquals(VaultGroupPublicationDecision.UNKNOWN, groups.publicationDecision(publication(awaiting)))
        }

    @Test fun cancellationAfterReservationRejectsCommitAndRetainsUnresolvedAuthorityAcrossHistoryClear() =
        runBlocking {
            val awaiting = awaiting()
            val exact = publication(awaiting)
            val reservation = requireNotNull(groups.reservePublication(awaiting, exact) { true })
            val cancelled = requireNotNull(groups.cancel(reservation.lease, 5))
            store.clearTransferHistory("a")
            assertNull(store.transfer(cancelled.group.id))
            assertFalse(groups.commitPublication(reservation, { true }, 6))
            assertEquals(VaultGroupPublicationDecision.REJECTED, groups.publicationDecision(exact))
            assertNull(groups.beginPreparation(exact.owner, descriptor()))
            assertFalse(groups.acknowledgeJournalResolved(exact, true))
            assertTrue(groups.acknowledgeJournalResolved(exact, false))
            assertTrue(groups.beginPreparation(exact.owner, descriptor()) != null)
            assertEquals(VaultGroupPublicationDecision.REJECTED, groups.publicationDecision(exact))
        }

    @Test fun committedReceiptSurvivesParentHistoryAndRejectsRootOrPlanSubstitution() =
        runBlocking {
            val awaiting = awaiting()
            val exact = publication(awaiting)
            val reservation = requireNotNull(groups.reservePublication(awaiting, exact) { true })
            assertFalse(groups.commitPublication(reservation, { false }, 4))
            val substituted = reservation.copy(publication = exact.copy(nextRootDigest = digest('9')))
            assertFalse(groups.commitPublication(substituted, { true }, 4))
            assertTrue(groups.commitPublication(reservation, { true }, 5))
            store.clearTransferHistory("a")
            assertNull(store.transfer(awaiting.group.id))
            assertTrue(groups.hasUnresolved(exact.owner, exact.groupId))
            assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(exact))
            assertEquals(
                VaultGroupPublicationDecision.UNKNOWN,
                groups.publicationDecision(exact.copy(nextRootDigest = digest('9'))),
            )
            assertEquals(
                VaultGroupPublicationDecision.UNKNOWN,
                groups.publicationDecision(exact.copy(planDigest = digest('8'))),
            )
            assertFalse(groups.acknowledgeJournalResolved(exact, false))
            assertTrue(groups.acknowledgeJournalResolved(exact, true))
            assertFalse(groups.hasUnresolved(exact.owner, exact.groupId))
            assertTrue(groups.acknowledgeJournalResolved(exact, true))
            assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(exact))
        }

    @Test fun removedAndIdenticallyReaddedAccountCannotReviveGroupAttemptOrReceipt() =
        runBlocking {
            val awaiting = awaiting()
            val oldOwner = awaiting.group.owner()
            val exact = publication(awaiting)
            val reservation = requireNotNull(groups.reservePublication(awaiting, exact) { true })
            store.removeAccount("a")
            database.accountDao().upsert(account)
            val replacement = requireNotNull(groups.captureOwner("a"))
            assertNotEquals(oldOwner.incarnation, replacement.incarnation)
            assertFalse(groups.isCurrentOwner(oldOwner))
            assertNull(groups.find(awaiting.group.id))
            assertFalse(groups.commitPublication(reservation, { error("Revoked owner invoked permit") }, 6))
            assertEquals(VaultGroupPublicationDecision.REVOKED, groups.publicationDecision(exact))
            assertThrows(IOException::class.java) { runBlocking { groups.memberPage(awaiting) } }
            Unit
        }

    @Test fun transportRetryRetainsSealButRotatesAttemptAndQueueWatermark() =
        runBlocking {
            val queued = queued(1)
            val attempt = requireNotNull(groups.claim(queued, uuid(), 2))
            val file = groups.memberPage(attempt.lease).single { it.kind == "FILE" }
            val cancelled = requireNotNull(groups.cancel(attempt.lease, 3))
            val bulk = requireNotNull(store.transferInventory().captureScope("a"))
            val retryWorker = uuid()
            val retry = requireNotNull(groups.retry(cancelled, retryWorker, 4, bulk))
            assertEquals(queued.group.sealedPlanDigest, retry.group.sealedPlanDigest)
            assertEquals(queued.group.baseOfflineRootDigest, retry.group.baseOfflineRootDigest)
            assertNull(store.transferInventory().cancelForClear(bulk, queued.group.id))
            assertNull(groups.checkpoint(attempt, file, VaultGroupCheckpoint("DOWNLOADED", 32, digest('7'))))
            assertNull(groups.claim(retry, uuid(), 5))
            val fresh = requireNotNull(groups.claim(retry, retryWorker, 5))
            assertNotEquals(attempt.attemptId, fresh.attemptId)
            val conflict = requireNotNull(groups.fail(fresh.lease, "BASE_OFFLINE_ROOT_CHANGED", 6))
            assertNull(groups.retry(conflict, uuid(), 7))
        }

    @Test fun deferredRetryPreservesWorkerDeadlineAndCountsAttemptsWithoutAdmittingOldClaim() =
        runBlocking {
            val worker = uuid()
            val attempt = requireNotNull(groups.claim(queued(1), worker, 2))
            assertEquals(1, attempt.lease.parent?.attemptCount)
            val deferred = requireNotNull(groups.deferRetry(attempt.lease, "RATE_LIMITED", 1000, 3))
            assertEquals("RETRY", deferred.group.state)
            assertEquals(worker, deferred.parent?.workId)
            assertNull(groups.deferRetry(attempt.lease, "TIMEOUT", 0, 4))
            assertNull(groups.claim(deferred, worker, 999))
            assertNull(groups.claim(deferred, uuid(), 1000))
            val fresh = requireNotNull(groups.claim(deferred, worker, 1000))
            assertEquals(2, fresh.lease.parent?.attemptCount)
            assertNotEquals(attempt.attemptId, fresh.attemptId)
            val conflict = requireNotNull(groups.fail(fresh.lease, "OFFLINE_SNAPSHOT_CHANGED", 1001))
            assertNull(groups.retry(conflict, uuid(), 1002))
        }

    @Test fun pendingObservationEmitsOnlyOneAwaitingIdentityAndRevisionForTheExactVault() =
        runBlocking {
            val queued = queued(0)
            assertNull(groups.observeAwaiting("a", "drive", "vault").first())
            val awaiting = requireNotNull(groups.awaitUnlock(requireNotNull(groups.claim(queued, uuid(), 2)), 3))
            assertEquals(
                "${awaiting.group.id}:${awaiting.group.revision}",
                groups.observeAwaiting("a", "drive", "vault").first(),
            )
            assertNull(groups.observeAwaiting("a", "other-drive", "vault").first())
            assertNull(groups.observeAwaiting("other-account", "drive", "vault").first())
            groups.cancel(awaiting, 4)
            assertNull(groups.observeAwaiting("a", "drive", "vault").first())
        }

    @Test fun exactRunningWorkIntentReclaimsWithFreshAttemptWhileWrongWorkerAndOldCasAreRefused() =
        runBlocking {
            val worker = uuid()
            val first = requireNotNull(groups.claim(queued(1), worker, 2))
            val member = groups.memberPage(first.lease).single { it.kind == "FILE" }
            assertNull(groups.claim(first.lease, uuid(), 3))
            val restarted = requireNotNull(groups.claim(first.lease, worker, 3))
            assertEquals(2, restarted.lease.parent?.attemptCount)
            assertNotEquals(first.attemptId, restarted.attemptId)
            assertNull(groups.checkpoint(first, member, VaultGroupCheckpoint("DOWNLOADED", 32, digest('f'))))
            assertTrue(
                groups.checkpoint(restarted, member, VaultGroupCheckpoint("DOWNLOADED", 32, digest('f'))) != null,
            )
        }

    @Test fun ordinaryClaimAndRetryCannotAdmitGroupAndScopedClearCancelsItsDurableState() =
        runBlocking {
            val queued = queued(1)
            assertNull(database.claimAllowedTransfer(queued.group.id, uuid(), 3))
            val bulk = requireNotNull(store.transferInventory().captureScope("a"))
            assertEquals(queued.parent, store.transferInventory().cancelForClear(bulk, queued.group.id))
            val cancelled = requireNotNull(groups.find(queued.group.id))
            assertEquals("CANCELLED", cancelled.group.state)
            val parent = requireNotNull(cancelled.parent)
            assertNull(store.transferInventory().retryScoped(bulk, parent, parent.copy(state = "QUEUED")))
        }

    @Test fun clearingFailedGroupKeepsStaleBaseRetryBlockedAndRemovesItsVisibleHistory() =
        runBlocking {
            val queued = queued(1)
            val failed = requireNotNull(groups.fail(queued, "OFFLINE_SNAPSHOT_CHANGED", 3))
            val bulk = requireNotNull(store.transferInventory().captureScope("a"))
            assertEquals(failed.parent, store.transferInventory().cancelForClear(bulk, queued.group.id))
            val cancelled = requireNotNull(groups.find(queued.group.id))
            assertEquals("CANCELLED", cancelled.group.state)
            assertEquals("OFFLINE_SNAPSHOT_CHANGED", cancelled.group.errorCode)
            assertNull(groups.retry(cancelled, uuid(), 4))
            assertEquals(1, store.transferInventory().deleteScopedHistory(bulk))
            assertNull(store.transfer(queued.group.id))
        }

    @Test fun accountSecurityReplacementRotatesOwnerWhileCapabilityRefreshPreservesIt() =
        runBlocking {
            val owner = requireNotNull(groups.captureOwner("a"))
            val queued = queued(1)
            database.upsertOwnedAccount(account.copy(displayName = "New display", tusSupported = true))
            assertEquals(owner, groups.captureOwner("a"))
            assertEquals("QUEUED", store.transfer(queued.group.id)?.state)
            database.upsertOwnedAccount(account.copy(serverUrl = "https://replacement.example.test"))
            val replacement = requireNotNull(groups.captureOwner("a"))
            assertNotEquals(owner.incarnation, replacement.incarnation)
            assertFalse(groups.isCurrentOwner(owner))
            assertEquals("CANCELLED", store.transfer(queued.group.id)?.state)
            assertNull(groups.find(queued.group.id))
        }

    private suspend fun queued(fileCount: Int): VaultGroupLease {
        val owner = requireNotNull(groups.captureOwner("a"))
        var lease = requireNotNull(groups.beginPreparation(owner, descriptor()))
        val rows = admissions(fileCount + 1)
        lease = requireNotNull(groups.appendMembers(lease, 0, rows, lease.group.stagingChainDigest, digest('c')))
        val seal =
            VaultGroupSeal(lease.group.planId, digest('d'), rows.size.toLong(), fileCount.toLong(), fileCount * 32L)
        return requireNotNull(groups.sealAndEnqueue(lease, seal, parent(lease, seal.ciphertextBytes)) { true })
    }

    private suspend fun awaiting(): VaultGroupLease {
        var attempt = requireNotNull(groups.claim(queued(1), uuid(), 2))
        val member = groups.memberPage(attempt.lease).single { it.kind == "FILE" }
        val completed = groups.checkpoint(attempt, member, VaultGroupCheckpoint("DOWNLOADED", 32, digest('f')))
        attempt = requireNotNull(completed).attempt
        return requireNotNull(groups.awaitUnlock(attempt, 3))
    }

    private fun admissions(count: Int) =
        (0 until count).map { index ->
            VaultGroupMemberAdmission(
                index.toLong(),
                uuid(),
                digest('a'),
                if (index == 0) "DIRECTORY" else "FILE",
                if (index == 0) null else uuid(),
            )
        }

    private fun descriptor(): VaultGroupDescriptor {
        val id = uuid()
        return VaultGroupDescriptor(id, "drive", "vault", digest('1'), id, digest('2'), digest('3'), id)
    }

    private fun parent(
        lease: VaultGroupLease,
        bytes: Long,
    ) = TransferEntity(
        id = lease.group.id,
        accountId = "a",
        spaceId = "drive",
        resourceId = null,
        direction = "DOWNLOAD",
        sourceUri = "vault-offline-group:vault",
        destinationPath = "encrypted/root",
        displayName = "Encrypted offline folder",
        mimeType = null,
        bytesTotal = bytes,
        offlinePin = true,
        locationKind = VAULT_GROUP_LOCATION_KIND,
        createdAtEpochMillis = 1,
        updatedAtEpochMillis = 1,
    )

    private fun publication(lease: VaultGroupLease) =
        VaultGroupPublication(
            uuid(),
            lease.group.id,
            lease.group.owner(),
            lease.group.identityDigest,
            lease.group.descriptorDigest,
            requireNotNull(lease.group.sealedPlanDigest),
            requireNotNull(lease.group.sealedMemberCount),
            lease.group.baseOfflineRootDigest,
            digest('4'),
        )

    private fun uuid() = UUID.randomUUID().toString()

    private fun digest(char: Char) = char.toString().repeat(64)
}
