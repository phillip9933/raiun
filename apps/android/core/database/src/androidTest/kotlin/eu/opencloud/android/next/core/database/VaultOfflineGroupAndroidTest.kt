package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class VaultOfflineGroupAndroidTest {
    @Test fun fileBackedOwnershipAndPublicationAuthoritySurviveReopenAndHistoryButNotAccountRecreation() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val name = "vault-offline-group-${UUID.randomUUID()}.db"

            fun open() = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            var database = open()
            try {
                val account = AccountEntity("a", "https://example.test", "u", "U", "BASIC", false)
                database.accountDao().upsert(account)
                var groups = FileBrowserStore(database).vaultOfflineGroups()
                val owner = requireNotNull(groups.captureOwner("a"))
                val id = UUID.randomUUID().toString()
                val digest = "a".repeat(64)
                var lease =
                    requireNotNull(
                        groups.beginPreparation(
                            owner,
                            VaultGroupDescriptor(id, "drive", "vault", digest, id, digest, digest, id),
                        ),
                    )
                lease =
                    requireNotNull(
                        groups.appendMembers(
                            lease,
                            0,
                            listOf(VaultGroupMemberAdmission(0, UUID.randomUUID().toString(), digest, "DIRECTORY")),
                            lease.group.stagingChainDigest,
                            digest,
                        ),
                    )
                val transfer =
                    TransferEntity(
                        id,
                        "a",
                        "drive",
                        null,
                        "DOWNLOAD",
                        "vault-offline-group:vault",
                        "opaque/root",
                        "Encrypted offline folder",
                        null,
                        0,
                        offlinePin = true,
                        locationKind = VAULT_GROUP_LOCATION_KIND,
                        createdAtEpochMillis = 1,
                        updatedAtEpochMillis = 1,
                    )
                lease =
                    requireNotNull(groups.sealAndEnqueue(lease, VaultGroupSeal(id, digest, 1, 0, 0), transfer) { true })
                val attempt = requireNotNull(groups.claim(lease, UUID.randomUUID().toString(), 2))
                lease = requireNotNull(groups.awaitUnlock(attempt, 3))
                val publication =
                    VaultGroupPublication(
                        UUID.randomUUID().toString(),
                        id,
                        owner,
                        digest,
                        digest,
                        digest,
                        1,
                        digest,
                        "b".repeat(64),
                    )
                val reserved = requireNotNull(groups.reservePublication(lease, publication) { true })
                assertTrue(groups.commitPublication(reserved, { true }, 4))
                database.close()
                database = open()
                val store = FileBrowserStore(database)
                groups = store.vaultOfflineGroups()
                assertEquals(owner, groups.captureOwner("a"))
                assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(publication))
                store.clearTransferHistory("a")
                assertNull(store.transfer(id))
                assertEquals(VaultGroupPublicationDecision.ACCEPTED, groups.publicationDecision(publication))
                assertTrue(groups.acknowledgeJournalResolved(publication, true))
                store.removeAccount("a")
                database.accountDao().upsert(account)
                val fresh = requireNotNull(groups.captureOwner("a"))
                assertNotEquals(owner.incarnation, fresh.incarnation)
                assertFalse(groups.isCurrentOwner(owner))
                assertEquals(VaultGroupPublicationDecision.REVOKED, groups.publicationDecision(publication))
                assertNull(groups.find(id))
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }
}
