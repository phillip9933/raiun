package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SharedDownloadStoreTest {
    private val context = RuntimeEnvironment.getApplication()
    private val name = "sd.db"
    private var database = openDatabase()

    private fun openDatabase() =
        Room
            .databaseBuilder(context, FileBrowserDatabase::class.java, name)
            .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
            .build()

    private val inventory get() = IncomingShareStore(database)
    private val downloads get() = SharedDownloadStore(database)
    private val localFiles get() = SharedLocalFileStore(database)
    private val commit = SharedFileCommit("/private/verified-file", 12, "a".repeat(64), 5)
    private val share = IncomingShareEntity("a", "share", "root", "Folder", true, null, "{}")
    private val scope = SharedFolderScopeEntity("a", "scope", "share", "drive", "root", "https://example.test/root/")
    private val entry = SharedFolderEntry("a", "scope", "file", "/", "/file", "file", false, null, 12, "v1", 0, 0)

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            inventory.replace("a", inventory.beginRefresh("a"), listOf(share))
            saveEntry(entry)
        }

    @After fun close() {
        database.close()
        context.deleteDatabase(name)
    }

    @Test fun publishAndHistoryRetention() =
        runBlocking {
            val record = running("one")
            val active = record.transfer.copy(offlinePin = true)
            database.transferDao().update(active)
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            assertEquals(SharedFilePublication(null), localFiles.publish(lease, record, commit))
            val completed = requireNotNull(database.transferDao().findById("one"))
            assertEquals("SUCCEEDED", completed.state)
            assertEquals(12L, completed.bytesTransferred)
            assertTrue(requireNotNull(localFiles.read(lease, entry)).offlinePinned)
            assertNull(localFiles.publish(lease, record, commit))
            FileBrowserStore(database).clearTransferHistory("a")
            assertEquals(commit.sha256, localFiles.read(lease, entry)?.sha256)
            database.close()
            database = openDatabase()
            assertEquals(
                commit.localPath,
                localFiles.read(requireNotNull(inventory.beginAccess("a", "share")), entry)?.localPath,
            )
        }

    @Test fun cancelledOrReplacedOwnerCannotPublish() =
        runBlocking {
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            val cancelled = running("cancelled")
            database.transferDao().cancel(cancelled.transfer.id)
            assertNull(localFiles.publish(lease, cancelled, commit))
            val replaced = running("replaced")
            database.transferDao().update(replaced.transfer.copy(workId = "different-worker"))
            assertNull(localFiles.publish(lease, replaced, commit))
            assertNull(localFiles.read(lease, entry))
        }

    @Test fun changedLeaseOrFileCannotPublish() =
        runBlocking {
            val record = running("one")
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            inventory.beginRefresh("a")
            assertNull(localFiles.publish(lease, record, commit))
            val currentLease = requireNotNull(inventory.beginAccess("a", "share"))
            saveEntry(entry.copy(eTag = "v2"))
            assertNull(localFiles.publish(currentLease, record, commit))
            assertEquals("CANCELLED", database.transferDao().findById("one")?.state)
            assertNull(database.sharedLocalFileDao().find("a", "scope", "file"))
        }

    @Test fun evidenceValidationAndChangedCache() =
        runBlocking {
            val record = running("one")
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            for (invalid in listOf(
                commit.copy(sizeBytes = 11),
                commit.copy(sha256 = "invalid"),
                commit.copy(localPath = ""),
            )) {
                assertThrows(
                    IllegalArgumentException::class.java,
                ) { runBlocking { localFiles.publish(lease, record, invalid) } }
                assertEquals("RUNNING", database.transferDao().findById("one")?.state)
                assertNull(localFiles.read(lease, entry))
            }
            localFiles.publish(lease, record, commit)
            val changed = entry.copy(eTag = "v2")
            saveEntry(changed)
            assertNull(localFiles.read(lease, entry))
            assertNull(localFiles.read(lease, changed))
        }

    @Test fun replacementAndScopeCleanup() =
        runBlocking {
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            localFiles.publish(lease, running("one"), commit)
            val replacement = commit.copy(localPath = "/private/new-file")
            assertEquals(
                SharedFilePublication(commit.localPath),
                localFiles.publish(lease, running("two"), replacement),
            )
            inventory.replace("a", inventory.beginRefresh("a"), emptyList())
            assertNull(database.sharedLocalFileDao().find("a", "scope", "file"))
            assertNull(localFiles.read(lease, entry))
            inventory.replace("a", inventory.beginRefresh("a"), listOf(share))
            saveEntry(entry)
            assertNull(localFiles.read(requireNotNull(inventory.beginAccess("a", "share")), entry))
        }

    private suspend fun running(id: String): SharedDownloadRecord {
        enqueue(transfer(id))
        database.transferDao().claim(id, "worker-$id", 2)
        return requireNotNull(downloads.read(id))
    }

    @Test fun separateRootsKeepSeparateIntents() =
        runBlocking {
            enqueue(transfer("one"))
            val otherScope = scope.copy(scopeId = "other", rootWebDavUrl = "https://example.test/other/")
            val otherEntry = entry.copy(scopeId = "other")
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            val cache = SharedFolderCacheStore(database)
            cache.save(lease, requireNotNull(cache.begin(lease, otherScope, "/")), otherScope, "/", listOf(otherEntry))
            val otherTransfer = transfer("two").copy(spaceId = "other")
            assertEquals(otherTransfer, downloads.enqueue(lease, otherScope, otherEntry, otherTransfer))
            assertEquals(2, queueSize())
            assertEquals("scope", downloads.read("one")?.intent?.scopeId)
            assertEquals("other", downloads.read("two")?.intent?.scopeId)
        }

    @Test fun restartKeepsIntentAndQueue() =
        runBlocking {
            val transfer = transfer("one")
            assertEquals(transfer, enqueue(transfer))
            assertEquals(1, queueSize())
            database.close()
            database = openDatabase()
            val record = requireNotNull(downloads.read("one"))
            assertEquals(transfer, record.transfer)
            assertEquals("drive", record.scope.serverDriveId)
            assertEquals("scope", record.intent.scopeId)
            assertEquals("v1", record.intent.eTag)
            assertEquals(1, queueSize())
            assertTrue(FileBrowserStore(database).spaces("a").isEmpty())
        }

    @Test fun duplicatesRetainPin() =
        runBlocking {
            enqueue(transfer("one"))
            val joined = requireNotNull(enqueue(transfer("two").copy(offlinePin = true)))
            assertEquals("one", joined.id)
            assertTrue(joined.offlinePin)
            assertNull(database.transferDao().findById("two"))
            assertNull(database.sharedDownloadDao().find("two"))
            assertEquals(1, queueSize())
            val claimed = requireNotNull(database.transferDao().claim("one", "worker", 2))
            assertEquals("RUNNING", claimed.state)
            assertEquals("worker", downloads.read("one")?.transfer?.workId)
        }

    @Test fun staleSelectionIsRejected() =
        runBlocking {
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            inventory.beginRefresh("a")
            assertNull(downloads.enqueue(lease, scope, entry, transfer("stale")))
            assertEquals(0, queueSize())
            enqueue(transfer("one"))
            val changed = entry.copy(eTag = "v2")
            saveEntry(changed)
            assertNull(enqueue(transfer("old")))
            val fresh = transfer("new").copy(expectedETag = "v2")
            assertEquals(
                fresh,
                downloads.enqueue(
                    requireNotNull(inventory.beginAccess("a", "share")),
                    scope,
                    changed,
                    fresh,
                ),
            )
            assertNull(downloads.read("one"))
            assertEquals("CANCELLED", database.transferDao().findById("one")?.state)
            assertEquals("v2", downloads.read("new")?.intent?.eTag)
            assertEquals(2, queueSize())
        }

    @Test fun `shared subtree exclusion blocks new intents reads and late local publication`() =
        runBlocking {
            val lease = requireNotNull(inventory.beginAccess("a", "share"))
            database.sharedVaultExclusionDao().record(SharedVaultExclusion("a", scope.scopeId, "/file"))
            assertNull(downloads.enqueue(lease, scope, entry, transfer("blocked")))
            assertNull(database.transferDao().findById("blocked"))

            database.sharedVaultExclusionDao().confirmPlain("a", scope.scopeId, "/file")
            val active = running("active")
            database.sharedVaultExclusionDao().record(SharedVaultExclusion("a", scope.scopeId, "/file"))
            assertNull(downloads.read("active"))
            assertNull(localFiles.publish(lease, active, commit))
            assertNull(localFiles.read(lease, entry))
            assertEquals("RUNNING", database.transferDao().findById("active")?.state)
        }

    @Test fun invalidBindingIsRejected() =
        runBlocking {
            assertThrows(
                IllegalArgumentException::class.java,
            ) { runBlocking { enqueue(transfer("bad").copy(spaceId = "drive")) } }
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { FileBrowserStore(database).enqueueTransfer(transfer("ordinary-api")) }
            }
            assertEquals(0, queueSize())
            assertNull(downloads.read("bad"))
        }

    @Test fun removedShareCannotReviveIntent() =
        runBlocking {
            enqueue(transfer("one"))
            inventory.replace("a", inventory.beginRefresh("a"), emptyList())
            assertNull(downloads.read("one"))
            assertNull(database.sharedDownloadDao().find("one"))
            val retained = requireNotNull(database.transferDao().findById("one"))
            assertEquals("SHARED_FOLDER", retained.locationKind)
            assertNull(FileBrowserStore(database).retryTransfer(retained, retained))
            inventory.replace("a", inventory.beginRefresh("a"), listOf(share))
            saveEntry(entry)
            assertNull(downloads.read("one"))
        }

    @Test fun historyAndAccountCleanup() =
        runBlocking {
            val transfer = requireNotNull(enqueue(transfer("one")))
            database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            FileBrowserStore(database).clearTransferHistory("a")
            assertNull(database.sharedDownloadDao().find("one"))
            enqueue(transfer("two"))
            FileBrowserStore(database).removeAccount("a")
            assertNull(database.sharedDownloadDao().find("two"))
            assertNull(database.transferDao().findById("two"))
            assertEquals(0, queueSize())
        }

    private suspend fun enqueue(value: TransferEntity) =
        downloads.enqueue(
            requireNotNull(inventory.beginAccess("a", "share")),
            scope,
            entry,
            value,
        )

    private suspend fun saveEntry(value: SharedFolderEntry) {
        val lease = requireNotNull(inventory.beginAccess("a", "share"))
        val cache = SharedFolderCacheStore(database)
        assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(value)))
    }

    private fun queueSize(): Int =
        database.openHelper.readableDatabase.query("SELECT * FROM transfer_queue").use {
            it.count
        }

    private fun transfer(id: String) =
        TransferEntity(
            id,
            "a",
            "scope",
            "file",
            "DOWNLOAD",
            null,
            "/file",
            "file",
            null,
            12,
            createdAtEpochMillis = 1,
            updatedAtEpochMillis = 1,
            expectedETag = "v1",
            locationKind = "SHARED_FOLDER",
        )
}
