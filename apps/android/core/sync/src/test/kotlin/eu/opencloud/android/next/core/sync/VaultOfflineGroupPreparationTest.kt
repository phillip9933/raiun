package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class VaultOfflineGroupPreparationTest {
    private val context = RuntimeEnvironment.getApplication()
    private val root = File(context.cacheDir, "group-preparation-${UUID.randomUUID()}")
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
    private val selected = entry("vault-id", location.vaultPath, true)
    private val material = ByteArray(80) { it.toByte() }

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

    @Test fun completeTreeSealsAcrossPageBoundariesWithEmptyDirectoryAndOnlyOneTransfer() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val frozen = frozen(owner)
            source { path, consume ->
                if (path == selected.relativePath) {
                    repeat(131) { consume(entry("file-$it", "$path/RAW-$it", false)) }
                    consume(entry("empty", "$path/EMPTY", true))
                }
                listing(path)
            }.use { source ->
                val accepted = prepareVaultOfflineGroup(context, source, frozen, groups, plans) { true }
                assertEquals("QUEUED", accepted.state)
                assertEquals(131L * 97, accepted.bytesTotal)
                assertEquals(1, store.activeTransfers("account").size)
                plans.open(owner, accepted.id).use { opaque ->
                    assertEquals(133L, opaque.seal.memberCount)
                    assertEquals(131L, opaque.seal.fileCount)
                    opaque.verify(material, frozen).use { verified ->
                        var count = 0L
                        verified.visitVerified { count++ }
                        assertEquals(133L, count)
                    }
                }
            }
        }

    @Test fun emptySelectedDirectoryStillHasOneSealedMemberAndZeroContentBytes() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            source { path, _ -> listing(path) }.use { source ->
                val accepted = prepareVaultOfflineGroup(context, source, frozen(owner), groups, plans) { true }
                assertEquals(0L, accepted.bytesTotal)
                plans.open(owner, accepted.id).use { assertEquals(1L, it.seal.memberCount) }
            }
        }

    @Test fun lateParentReplacementLeavesNoVisibleTransferOrActiveGroup() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val frozen = frozen(owner)
            source { path, consume ->
                consume(entry("file", "$path/RAW", false))
                listing(path).copy(root = selected.copy(id = "replacement"))
            }.use { source ->
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { prepareVaultOfflineGroup(context, source, frozen, groups, plans) { true } }
                    }
                assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            }
            assertNull(store.transfer(frozen.groupId))
            assertNull(groups.active(owner, identity.driveId, identity.remoteVaultId))
            assertEquals("CANCELLED", groups.find(frozen.groupId)?.group?.state)
        }

    @Test fun anotherPreparationCannotReplaceAnAcceptedGroup() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val first =
                source { path, _ -> listing(path) }.use { source ->
                    prepareVaultOfflineGroup(context, source, frozen(owner), groups, plans) { true }
                }
            source { path, _ -> listing(path) }.use { source ->
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { prepareVaultOfflineGroup(context, source, frozen(owner), groups, plans) { true } }
                    }
                assertEquals(OpenCloudError.OfflineGroupBusy, failure.error)
            }
            assertEquals(first, store.transfer(first.id))
            assertEquals(first.id, groups.active(owner, identity.driveId, identity.remoteVaultId)?.group?.id)
        }

    @Test fun databaseFailureDuringCleanupStillReleasesThePrivatePreparation() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val frozen = frozen(owner)
            source { _, _ ->
                database.close()
                throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
            }.use { source ->
                assertThrows(Exception::class.java) {
                    runBlocking { prepareVaultOfflineGroup(context, source, frozen, groups, plans) { true } }
                }
            }
            assertFalse(plans.hasActivePreparation(owner, frozen.groupId))
        }

    private fun frozen(owner: eu.opencloud.android.next.core.database.VaultGroupOwner) =
        VaultOfflineGroupContext(
            UUID.randomUUID().toString(),
            owner,
            identity,
            location,
            selected.relativePath,
            null,
            "a".repeat(64),
        )

    private fun source(stream: (String, (VaultDavEntry) -> Unit) -> VaultDavListing) =
        VaultOfflineGroupSource(
            context,
            identity,
            location,
            selected,
            null,
            material.copyOf(),
            {},
            {},
            { "decoded-$it" },
            { path, _, consume -> stream(path, consume) },
        )

    private fun listing(path: String): VaultDavListing {
        val current = if (path == selected.relativePath) selected else entry("empty", path, true)
        return VaultDavListing(current, emptyList(), null, true)
    }

    private fun entry(
        id: String,
        path: String,
        folder: Boolean,
    ) = VaultDavEntry(
        id,
        path,
        path.substringAfterLast('/'),
        folder,
        if (folder) 0 else 97,
        "\"version\"",
        resolveEntryHref(location.rootWebDavUrl, path),
    )
}
