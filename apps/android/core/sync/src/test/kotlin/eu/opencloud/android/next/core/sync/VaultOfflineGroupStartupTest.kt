package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupStartupTest {
    private val context = RuntimeEnvironment.getApplication()
    private val root = File(context.cacheDir, "group-startup-${UUID.randomUUID()}")
    private val plans = VaultOfflineGroupPlanStore(root, jvmOfflineDurability(root))
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val location =
        VaultLocation(
            "account",
            "",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "root-id",
            "https://example.test/",
            "https://example.test/dav/files/",
            "Secret.vault",
            true,
        )
    private val identity = VaultIdentity("account", location.canonicalServer, "drive", "vault-id")
    private val selected =
        VaultDavEntry(
            "vault-id",
            location.vaultPath,
            "Secret.vault",
            true,
            0,
            null,
            resolveEntryHref(location.rootWebDavUrl, location.vaultPath),
        )

    @Before fun setup() =
        runBlocking {
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            store = FileBrowserStore(database)
            database.accountDao().upsert(
                AccountEntity("account", location.canonicalServer, "user", "User", "BASIC", false),
            )
        }

    @After fun close() {
        database.close()
        root.deleteRecursively()
    }

    @Test fun livePrivatePreparationSurvivesGeneralCleanup() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val frozen = frozen(owner)
            plans.begin(frozen).use {
                val expected = requireNotNull(groups.beginPreparation(owner, frozen.descriptor()))
                reconcileVaultOfflineGroups(context, store, plans)
                assertEquals(expected, groups.find(frozen.groupId))
            }
        }

    @Test fun abandonedPreparationIsCancelledAndCannotBlockANewGroup() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val frozen = frozen(owner)
            plans.begin(frozen).use { groups.beginPreparation(owner, frozen.descriptor()) }
            reconcileVaultOfflineGroups(context, store, plans)
            assertEquals("CANCELLED", groups.find(frozen.groupId)?.group?.state)
            assertNull(groups.active(owner, identity.driveId, identity.remoteVaultId))
            assertNotNull(groups.beginPreparation(owner, frozen(owner).descriptor()))
        }

    @Test fun terminalHistoryRemovalReclaimsOnlyItsUnownedPrivatePlan() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val parent = accepted(owner)
            val expected = requireNotNull(groups.find(parent.id))
            groups.cancel(expected, 2_000)
            store.clearTransferHistory("account")
            reconcileVaultOfflineGroups(context, store, plans)
            assertNull(store.transfer(parent.id))
            assertThrows(Exception::class.java) { plans.open(owner, parent.id) }
            Unit
        }

    @Test fun unresolvedPublicationRetainsItsPlanAfterParentHistoryDisappears() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val parent = accepted(owner)
            val queued = requireNotNull(groups.find(parent.id))
            val attempt = requireNotNull(groups.claim(queued, UUID.randomUUID().toString(), 2_000))
            val waiting = requireNotNull(groups.awaitUnlock(attempt, 2_001))
            val group = waiting.group
            val exact =
                VaultGroupPublication(
                    UUID.randomUUID().toString(),
                    group.id,
                    owner,
                    group.identityDigest,
                    group.descriptorDigest,
                    requireNotNull(group.sealedPlanDigest),
                    requireNotNull(group.sealedMemberCount),
                    group.baseOfflineRootDigest,
                    "b".repeat(64),
                )
            val reservation = requireNotNull(groups.reservePublication(waiting, exact) { true })
            groups.cancel(reservation.lease, 2_002)
            store.clearTransferHistory("account")
            reconcileVaultOfflineGroups(context, store, plans)
            assertNull(store.transfer(parent.id))
            plans.open(owner, parent.id).use { assertEquals(parent.id, it.context.groupId) }
        }

    private suspend fun accepted(owner: VaultGroupOwner) =
        VaultOfflineGroupSource(
            context,
            identity,
            location,
            selected,
            null,
            ByteArray(80) { it.toByte() },
            {},
            {},
            { it },
            { _, _, _ -> VaultDavListing(selected, emptyList(), null, true) },
        ).use { source ->
            prepareVaultOfflineGroup(context, source, frozen(owner), store.vaultOfflineGroups(), plans) { true }
        }

    private fun frozen(owner: VaultGroupOwner) =
        VaultOfflineGroupContext(
            UUID.randomUUID().toString(),
            owner,
            identity,
            location,
            selected.relativePath,
            null,
            "a".repeat(64),
        )
}
