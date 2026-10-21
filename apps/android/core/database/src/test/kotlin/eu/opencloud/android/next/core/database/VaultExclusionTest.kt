package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class VaultExclusionTest {
    @Test fun `offline pin rejects stale or excluded resources but permits stale unpin`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                db.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                db.spaceDao().upsertAll(
                    listOf(SpaceEntity("a", "s", "Space", "personal", null, null, "root", null, null, null)),
                )
                val resource =
                    ResourceEntity(
                        "a",
                        "s",
                        "file",
                        null,
                        "/vault/file",
                        "file",
                        eu.opencloud.android.next.core.model.ResourceKind.FILE,
                        null,
                        1,
                        "v1",
                        0,
                        0,
                    )
                db.resourceDao().upsert(resource)
                val store = FileBrowserStore(db)
                db.vaultExclusionDao().record(VaultExclusion("a", "s", "/vault"))
                assertRejected { store.setOfflinePinned(resource, true) }
                assertEquals(false, db.resourceDao().findById("a", "s", "file")?.offlinePinned)
                store.setOfflinePinned(resource.copy(eTag = "stale"), false)
                db.vaultExclusionDao().confirmPlain("a", "s", "/vault")
                assertRejected { store.setOfflinePinned(resource.copy(eTag = "stale"), true) }
                store.setOfflinePinned(resource, true)
                assertEquals(true, db.resourceDao().findById("a", "s", "file")?.offlinePinned)
            } finally {
                db.close()
            }
        }

    @Test fun `excluded folder does not block a sibling destination and moved parent is stale`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                db.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                db.spaceDao().upsertAll(
                    listOf(SpaceEntity("a", "s", "Space", "personal", null, null, "root", null, null, null)),
                )
                val parent =
                    ResourceEntity(
                        "a",
                        "s",
                        "parent",
                        null,
                        "/allowed",
                        "allowed",
                        eu.opencloud.android.next.core.model.ResourceKind.FOLDER,
                        null,
                        0,
                        "v1",
                        0,
                        0,
                    )
                db.resourceDao().upsert(parent)
                val store = FileBrowserStore(db)
                db.vaultExclusionDao().record(VaultExclusion("a", "s", "/allowed/secret"))
                val current = store.requireCurrentMutableResource(parent, includeDescendants = false)
                store.requireAllowedFolderDestination("a", "s", "parent", current.path, "/allowed/new")
                assertRejected {
                    store.requireAllowedFolderDestination("a", "s", "parent", current.path, "/allowed/secret/new")
                }
                db.resourceDao().upsert(parent.copy(path = "/moved"))
                var stale = false
                try {
                    store.requireAllowedFolderDestination("a", "s", "parent", current.path, "/allowed/new")
                } catch (_: StaleResourceException) {
                    stale = true
                }
                assertTrue(stale)
            } finally {
                db.close()
            }
        }

    @Test fun `exclusions survive reopen and use literal scope boundaries`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val name = "vault-exclusion-test.db"
            context.deleteDatabase(name)
            var db = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            try {
                db.vaultExclusionDao().record(VaultExclusion("a", "s", "/a_%"))
                db.close()
                db = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
                val dao = db.vaultExclusionDao()
                assertTrue(dao.denies("a", "s", "/a_%/photo"))
                assertTrue(dao.denies("a", "s", "/", true))
                assertFalse(dao.denies("a", "s", "/"))
                assertFalse(dao.denies("a", "s", "/a_%more/photo"))
                assertFalse(dao.denies("b", "s", "/a_%/photo"))
                dao.confirmPlain("a", "s", "/a_%")
                assertFalse(dao.denies("a", "s", "/a_%/photo"))
            } finally {
                db.close()
                context.deleteDatabase(name)
            }
        }

    @Test fun `drive evidence prevents reenabled backups until confirmed plain`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val store = FileBrowserStore(db)
                val pair =
                    FolderBackupEntity(
                        "pair",
                        "a",
                        "s",
                        "content://source",
                        destinationPath = "/photos",
                        mediaType = "ALL",
                        wifiOnly = false,
                        chargingOnly = false,
                        deleteAfterUpload = false,
                    )
                store.saveBackup(pair)
                store.replaceRemoteSpaces("a", emptyList(), excludedVaultIds = setOf("s"))
                assertTrue(db.vaultExclusionDao().denies("a", "s", "/anything"))
                var rejected = false
                try {
                    store.saveBackup(pair)
                } catch (_: IllegalArgumentException) {
                    rejected = true
                }
                assertTrue(rejected)
                assertEquals(false, store.backup("pair")?.enabled)
                // Absence alone does not clear explicit encryption evidence.
                store.replaceRemoteSpaces("a", emptyList())
                assertTrue(db.vaultExclusionDao().denies("a", "s", "/anything"))
                val plain = SpaceEntity("a", "s", "Space", "personal", null, null, "root", null, null, null)
                store.replaceRemoteSpaces("a", listOf(plain))
                assertFalse(db.vaultExclusionDao().denies("a", "s", "/anything"))
                store.saveBackup(pair)
                assertEquals(true, store.backup("pair")?.enabled)
            } finally {
                db.close()
            }
        }

    @Test fun `exclusion blocks retries and claims without changing completed history`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val store = FileBrowserStore(db)
                db.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                db.spaceDao().upsertAll(
                    listOf(SpaceEntity("a", "s", "Space", "personal", null, null, "root", null, null, null)),
                )
                val original =
                    TransferEntity(
                        "old",
                        "a",
                        "s",
                        null,
                        "UPLOAD",
                        "content://file",
                        "/vault/file",
                        "file",
                        null,
                        1,
                        state = "FAILED",
                        createdAtEpochMillis = 0,
                        updatedAtEpochMillis = 0,
                    )
                store.createTransfer(original)
                db.vaultExclusionDao().record(VaultExclusion("a", "s", "/vault"))
                assertEquals(null, store.retryTransfer(original, original.copy(state = "QUEUED")))
                assertEquals(
                    null,
                    store.retryTransfer(original, original.copy(state = "QUEUED", destinationPath = "/elsewhere")),
                )
                val neighbor = original.copy(id = "neighbor", destinationPath = "/vault-other/file")
                store.createTransfer(neighbor)
                assertEquals(
                    null,
                    store.retryTransfer(neighbor, neighbor.copy(state = "QUEUED", destinationPath = "/vault/new")),
                )
                val allowed = neighbor.copy(state = "QUEUED")
                assertEquals(allowed, store.retryTransfer(neighbor, allowed))
                assertEquals("RUNNING", store.claimTransfer("neighbor", "worker", 1)?.state)
                store.createTransfer(original.copy(id = "queued", state = "QUEUED"))
                assertEquals(null, store.claimTransfer("queued", "worker", 1))
                assertEquals("CANCELLED", store.transfer("queued")?.state)
                store.createTransfer(original.copy(id = "done", state = "SUCCEEDED"))
                assertEquals(null, store.claimTransfer("done", "worker", 1))
                assertEquals("SUCCEEDED", store.transfer("done")?.state)
            } finally {
                db.close()
            }
        }

    private suspend fun assertRejected(action: suspend () -> Unit) {
        var rejected = false
        try {
            action()
        } catch (_: IllegalStateException) {
            rejected = true
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
    }
}
