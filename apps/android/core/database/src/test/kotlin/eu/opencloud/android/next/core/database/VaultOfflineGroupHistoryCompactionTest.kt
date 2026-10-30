package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupHistoryCompactionTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var groups: VaultOfflineGroups
    private val account = AccountEntity("a", "https://example.test", "user", "User", "BASIC", false)
    private val otherAccount = account.copy(id = "other")

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
            database.accountDao().upsert(otherAccount)
        }

    @After fun close() = database.close()

    @Test fun scopedClearCascadesLargeTerminalMemberHistoryAndPreservesLiveOrUnresolvedAuthority() =
        runBlocking {
            val largeOrphan = group("a", "SUCCEEDED", activeSlot = null).also { insert(it, 1_025) }
            val canceledWithParent =
                group("a", "CANCELLED", activeSlot = null).also {
                    insert(it, 3)
                    database.transferDao().insert(parent(it, "CANCELLED"))
                }
            val failedWithParent =
                group("a", "FAILED", activeSlot = null).also {
                    insert(it, 2)
                    database.transferDao().insert(parent(it, "FAILED"))
                }
            val preparing = group("a", "PREPARING", activeSlot = 1).also { insert(it, 2) }
            val otherAccountOrphan = group("other", "SUCCEEDED", activeSlot = null).also { insert(it, 2) }

            val unresolved = group("a", "CANCELLED", activeSlot = null).also { insert(it, 2) }
            val unresolvedPublication = publication(unresolved, "PREPARED", journalResolved = false)
            database.vaultOfflineGroupDao().insertPublication(unresolvedPublication)
            val unresolvedExact = unresolvedPublication.exact(unresolved.owner())

            val resolved = group("a", "SUCCEEDED", activeSlot = null).also { insert(it, 2) }
            val resolvedPublication = publication(resolved, "COMMITTED", journalResolved = true)
            database.vaultOfflineGroupDao().insertPublication(resolvedPublication)
            val resolvedExact = resolvedPublication.exact(resolved.owner())
            assertEquals(VaultGroupPublicationDecision.REJECTED, groups.publicationDecision(unresolvedExact))
            assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(resolvedExact))

            val scope = requireNotNull(store.transferInventory().captureScope(account.id))
            assertEquals(1, store.transferInventory().deleteScopedHistory(scope))

            assertNull(database.vaultOfflineGroupDao().group(largeOrphan.id))
            assertEquals(0L, memberCount(largeOrphan.id))
            assertNull(database.vaultOfflineGroupDao().group(canceledWithParent.id))
            assertEquals(0L, memberCount(canceledWithParent.id))
            assertNotNull(database.vaultOfflineGroupDao().group(failedWithParent.id))
            assertEquals(2L, memberCount(failedWithParent.id))
            assertEquals("FAILED", database.transferDao().findById(failedWithParent.id)?.state)
            assertNotNull(database.vaultOfflineGroupDao().group(preparing.id))
            assertNotNull(database.vaultOfflineGroupDao().group(otherAccountOrphan.id))

            assertNotNull(database.vaultOfflineGroupDao().group(unresolved.id))
            assertEquals(2L, memberCount(unresolved.id))
            assertTrue(groups.hasUnresolved(unresolved.owner(), unresolved.id))
            assertNull(database.vaultOfflineGroupDao().group(resolved.id))
            assertEquals(0L, memberCount(resolved.id))
            assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(resolvedExact))
            assertTrue(groups.acknowledgeJournalResolved(resolvedExact, retainedNext = true))
            assertFalse(groups.hasUnresolved(resolved.owner(), resolved.id))
            assertNull(database.transferDao().findById(canceledWithParent.id))
        }

    @Test fun fileBrowserClearHistoryUsesSameCompactionWithoutChangingTransferCount() =
        runBlocking {
            val orphan = group("a", "FAILED", activeSlot = null).also { insert(it, 4) }
            val transferGroup =
                group("a", "CANCELLED", activeSlot = null).also {
                    insert(it, 1)
                    database.transferDao().insert(parent(it, "CANCELLED"))
                }
            store.clearTransferHistory(account.id)
            assertNull(database.vaultOfflineGroupDao().group(orphan.id))
            assertNull(database.vaultOfflineGroupDao().group(transferGroup.id))
            assertEquals(0L, memberCount(orphan.id))
            assertEquals(0L, memberCount(transferGroup.id))
        }

    private suspend fun insert(
        group: VaultOfflineGroupEntity,
        memberCount: Int,
    ) {
        database.vaultOfflineGroupDao().insertGroup(group)
        repeat((memberCount + 127) / 128) { batch ->
            val first = batch * 128
            val last = minOf(memberCount, first + 128)
            database.vaultOfflineGroupDao().insertMembers(
                (first until last).map { index ->
                    VaultOfflineGroupMemberEntity(
                        groupId = group.id,
                        sequence = index.toLong(),
                        memberId = uuid(),
                        descriptorDigest = digest('d'),
                        kind = if (index == 0) "DIRECTORY" else "FILE",
                        state = "DOWNLOADED",
                    )
                },
            )
        }
    }

    private suspend fun group(
        accountId: String,
        state: String,
        activeSlot: Int?,
    ): VaultOfflineGroupEntity {
        val owner = requireNotNull(groups.captureOwner(accountId))
        return VaultOfflineGroupEntity(
            id = uuid(),
            accountId = accountId,
            accountIncarnation = owner.incarnation,
            driveId = uuid(),
            remoteVaultId = uuid(),
            accountIdentityDigest = owner.accountIdentityDigest,
            identityDigest = digest('i'),
            descriptorId = uuid(),
            descriptorDigest = digest('d'),
            baseOfflineRootDigest = digest('b'),
            planId = uuid(),
            sealedPlanDigest = digest('p'),
            sealedMemberCount = 1,
            sealedFileCount = 1,
            sealedCiphertextBytes = 4,
            stagedMemberCount = 1,
            stagingChainDigest = digest('s'),
            state = state,
            activeSlot = activeSlot,
            createdAtEpochMillis = 1,
            updatedAtEpochMillis = 1,
        )
    }

    private fun parent(
        group: VaultOfflineGroupEntity,
        state: String,
    ) = TransferEntity(
        id = group.id,
        accountId = group.accountId,
        spaceId = group.driveId,
        resourceId = null,
        direction = "DOWNLOAD",
        sourceUri = "vault-offline-group:${group.remoteVaultId}",
        destinationPath = "encrypted/root",
        displayName = "Encrypted offline folder",
        mimeType = "application/octet-stream",
        bytesTotal = 4,
        state = state,
        createdAtEpochMillis = 1,
        updatedAtEpochMillis = 1,
        locationKind = VAULT_GROUP_LOCATION_KIND,
    )

    private fun publication(
        group: VaultOfflineGroupEntity,
        state: String,
        journalResolved: Boolean,
    ) = VaultOfflineGroupPublicationEntity(
        publicationId = uuid(),
        groupId = group.id,
        accountId = group.accountId,
        accountIncarnation = group.accountIncarnation,
        identityDigest = group.identityDigest,
        descriptorDigest = group.descriptorDigest,
        sealedPlanDigest = requireNotNull(group.sealedPlanDigest),
        sealedMemberCount = requireNotNull(group.sealedMemberCount),
        baseOfflineRootDigest = group.baseOfflineRootDigest,
        nextOfflineRootDigest = digest('n'),
        reservedGroupRevision = group.revision,
        state = state,
        journalResolved = journalResolved,
        createdAtEpochMillis = 1,
        updatedAtEpochMillis = 1,
    )

    private suspend fun memberCount(groupId: String): Long = database.vaultOfflineGroupDao().counts(groupId).total

    private fun uuid() = UUID.randomUUID().toString()

    private fun digest(char: Char) = char.toString().repeat(64)
}

private fun VaultOfflineGroupPublicationEntity.exact(owner: VaultGroupOwner) =
    VaultGroupPublication(
        publicationId = publicationId,
        groupId = groupId,
        owner = owner,
        identityDigest = identityDigest,
        descriptorDigest = descriptorDigest,
        planDigest = sealedPlanDigest,
        memberCount = sealedMemberCount,
        baseRootDigest = baseOfflineRootDigest,
        nextRootDigest = nextOfflineRootDigest,
    )
