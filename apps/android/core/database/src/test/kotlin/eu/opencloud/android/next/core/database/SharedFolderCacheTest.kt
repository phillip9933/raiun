package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SharedFolderCacheTest {
    private data class SubtreeFixture(
        val child: SharedFolderEntry,
        val transfer: TransferEntity,
        val completedTransfer: TransferEntity,
    )

    private val context = RuntimeEnvironment.getApplication()
    private val name = "shared-cache.db"
    private var database = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
    private val account = AccountEntity("a", "https://example.test", "u", "User", "BASIC", false)
    private val share = IncomingShareEntity("a", "share", "root", "Folder", true, null, "{}")
    private val scope =
        SharedFolderScopeEntity("a", "local-one", "share", "drive", "root", "https://example.test/dav/one/")
    private val inventory get() = IncomingShareStore(database)
    private val cache get() = SharedFolderCacheStore(database)

    private suspend fun lease() = requireNotNull(inventory.beginAccess("a", "share"))

    private suspend fun seedSubtreeState(
        lease: IncomingShareLease,
        child: SharedFolderEntry,
        completedChild: SharedFolderEntry,
        ordinary: SharedFolderEntry,
    ): SubtreeFixture {
        val transfer =
            TransferEntity(
                "secret-download",
                "a",
                scope.scopeId,
                child.remoteId,
                "DOWNLOAD",
                null,
                child.path,
                child.name,
                child.mimeType,
                child.sizeBytes,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
                expectedETag = child.eTag,
                locationKind = "SHARED_FOLDER",
            )
        assertEquals(transfer, SharedDownloadStore(database).enqueue(lease, scope, child, transfer))
        database.transferDao().claim(transfer.id, "worker", 1)
        val completedTransfer =
            transfer.copy(
                id = "completed-history",
                resourceId = completedChild.remoteId,
                destinationPath = completedChild.path,
                displayName = completedChild.name,
            )
        assertEquals(
            completedTransfer,
            SharedDownloadStore(database).enqueue(lease, scope, completedChild, completedTransfer),
        )
        database.transferDao().update(completedTransfer.copy(state = "SUCCEEDED"))
        FileBrowserStore(database).createTransfer(
            transfer.copy(
                id = "secret-upload",
                direction = "UPLOAD",
                sourceUri = "content://staging/file",
                destinationPath = "/secret/new-file",
                displayName = "new-file",
                bytesTotal = 5,
                expectedETag = null,
            ),
        )
        database.sharedLocalFileDao().save(
            SharedLocalFile(
                "a",
                scope.scopeId,
                child.remoteId,
                child.path,
                child.sizeBytes,
                child.eTag,
                "/private/blob",
                "a".repeat(64),
                1,
                false,
            ),
        )
        database.sharedLocalFileDao().save(
            SharedLocalFile(
                "a",
                scope.scopeId,
                ordinary.remoteId,
                ordinary.path,
                ordinary.sizeBytes,
                ordinary.eTag,
                "/private/ordinary-blob",
                "d".repeat(64),
                1,
                true,
            ),
        )
        return SubtreeFixture(child, transfer, completedTransfer)
    }

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            inventory.replace("a", inventory.beginRefresh("a"), listOf(share))
            Unit
        }

    @After fun close() {
        database.close()
        context.deleteDatabase(name)
    }

    @Test fun `separate roots retain identical child identities without entering ordinary spaces`() =
        runBlocking {
            val lease = lease()
            val other = scope.copy(scopeId = "local-two", rootWebDavUrl = "https://example.test/dav/two/")
            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(entry())))
            val second = entry().copy(scopeId = other.scopeId, sizeBytes = 22)
            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, other, "/")), other, "/", listOf(second)))
            assertEquals(10L, cache.read(lease, scope, "/")?.single()?.sizeBytes)
            assertEquals(22L, cache.read(lease, other, "/")?.single()?.sizeBytes)
            assertTrue(FileBrowserStore(database).spaces("a").isEmpty())
        }

    @Test fun `newer folder refresh wins and consumed tokens cannot erase its cache`() =
        runBlocking {
            val lease = lease()
            val older = requireNotNull(cache.begin(lease, scope, "/"))
            val newer = requireNotNull(cache.begin(lease, scope, "/"))
            assertTrue(cache.save(lease, newer, scope, "/", listOf(entry())))
            assertFalse(cache.save(lease, older, scope, "/", emptyList()))
            assertFalse(cache.save(lease, newer, scope, "/", emptyList()))
            assertEquals(listOf(entry()), cache.read(lease, scope, "/"))
        }

    @Test fun `invalid replacement preserves cache and confirmed folder removal clears descendants`() =
        runBlocking {
            val lease = lease()
            val folder = entry().copy(remoteId = "folder", path = "/folder", name = "folder", isFolder = true)
            cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(folder))
            val child = entry().copy(parentPath = "/folder", path = "/folder/file")
            cache.save(lease, requireNotNull(cache.begin(lease, scope, "/folder")), scope, "/folder", listOf(child))
            val token = requireNotNull(cache.begin(lease, scope, "/"))
            val pendingChild = requireNotNull(cache.begin(lease, scope, "/folder"))
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { cache.save(lease, token, scope, "/", listOf(entry().copy(accountId = "other"))) }
            }
            assertEquals(listOf(folder), cache.read(lease, scope, "/"))
            assertTrue(cache.save(lease, token, scope, "/", emptyList()))
            assertFalse(cache.save(lease, pendingChild, scope, "/folder", listOf(child)))
            assertNull(cache.read(lease, scope, "/folder"))
            assertEquals(emptyList<SharedFolderEntry>(), cache.read(lease, scope, "/"))
        }

    @Test fun `refresh revokes old reads and writes and account removal cascades stored metadata`() =
        runBlocking {
            val lease = lease()
            cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(entry()))
            val pending = requireNotNull(cache.begin(lease, scope, "/"))
            inventory.beginRefresh("a")
            assertNull(cache.read(lease, scope, "/"))
            assertFalse(cache.save(lease, pending, scope, "/", emptyList()))
            FileBrowserStore(database).removeAccount("a")
            assertNull(database.sharedFolderCacheDao().scope("a", scope.scopeId))
            assertTrue(database.sharedFolderCacheDao().children("a", scope.scopeId, "/").isEmpty())
        }

    @Test fun `cache survives reopening but the old process lease does not authorize it`() =
        runBlocking {
            val old = lease()
            cache.save(old, requireNotNull(cache.begin(old, scope, "/")), scope, "/", listOf(entry()))
            database.close()
            database = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            assertNull(cache.read(old, scope, "/"))
            assertEquals(listOf(entry()), cache.read(lease(), scope, "/"))
            assertNull(cache.read(lease(), scope, "/never-fetched"))
        }

    @Test fun `only a complete inventory removing a share prunes its cached metadata`() =
        runBlocking {
            val lease = lease()
            cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(entry()))
            val pending = inventory.beginRefresh("a")
            assertEquals(scope, database.sharedFolderCacheDao().scope("a", scope.scopeId))
            inventory.replace("a", pending, emptyList())
            assertNull(database.sharedFolderCacheDao().scope("a", scope.scopeId))
            assertTrue(database.sharedFolderCacheDao().children("a", scope.scopeId, "/").isEmpty())
            assertFalse(database.sharedFolderCacheDao().hasPage("a", scope.scopeId, "/"))
        }

    @Test fun `vault drive exclusion revokes shared scopes and prevents late publication`() =
        runBlocking {
            val lease = lease()
            cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(entry()))
            val other = scope.copy(scopeId = "unrelated", serverDriveId = "other-drive")
            val otherEntry = entry().copy(scopeId = other.scopeId)
            cache.save(lease, requireNotNull(cache.begin(lease, other, "/")), other, "/", listOf(otherEntry))
            val pending = requireNotNull(cache.begin(lease, scope, "/"))
            val transfer =
                TransferEntity(
                    "shared",
                    "a",
                    scope.scopeId,
                    "file",
                    "DOWNLOAD",
                    null,
                    "/file",
                    "file",
                    "text/plain",
                    10,
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                    locationKind = "SHARED_FOLDER",
                )
            FileBrowserStore(database).createTransfer(transfer)
            FileBrowserStore(database).createTransfer(transfer.copy(id = "history", state = "SUCCEEDED"))
            FileBrowserStore(database).createTransfer(transfer.copy(id = "other", spaceId = other.scopeId))
            FileBrowserStore(database).replaceRemoteSpaces("a", emptyList(), excludedVaultIds = setOf("drive"))
            assertNull(database.sharedFolderCacheDao().scope("a", scope.scopeId))
            assertTrue(database.sharedFolderCacheDao().children("a", scope.scopeId, "/").isEmpty())
            assertNull(cache.read(lease, scope, "/"))
            assertNull(cache.begin(lease, scope, "/"))
            assertFalse(cache.save(lease, pending, scope, "/", listOf(entry())))
            assertEquals("CANCELLED", database.transferDao().findById("shared")?.state)
            assertEquals("SUCCEEDED", database.transferDao().findById("history")?.state)
            assertEquals("QUEUED", database.transferDao().findById("other")?.state)
            assertEquals(listOf(otherEntry), cache.read(lease, other, "/"))
        }

    @Test fun `shared subtree exclusion removes descendant state and survives scope removal`() =
        runBlocking {
            val lease = lease()
            val secretFolder = entry().copy(remoteId = "secret", path = "/secret", name = "secret", isFolder = true)
            val safeFolder = entry().copy(remoteId = "safe", path = "/safe", name = "safe", isFolder = true)
            val ordinary = entry().copy(remoteId = "ordinary", path = "/ordinary", name = "ordinary")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/")),
                    scope,
                    "/",
                    listOf(secretFolder, safeFolder, ordinary),
                ),
            )
            val child = entry().copy(parentPath = "/secret", path = "/secret/file")
            val completedChild = child.copy(remoteId = "completed", path = "/secret/completed", name = "completed")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/secret")),
                    scope,
                    "/secret",
                    listOf(child, completedChild),
                ),
            )
            val staleToken = requireNotNull(cache.begin(lease, scope, "/secret"))
            val fixture = seedSubtreeState(lease, child, completedChild, ordinary)
            val transfer = fixture.transfer
            val completedTransfer = fixture.completedTransfer

            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/")),
                    scope,
                    "/",
                    SharedFolderListing(listOf(safeFolder), setOf("/secret")),
                ),
            )
            assertEquals(listOf(safeFolder), cache.read(lease, scope, "/"))
            assertNull(cache.read(lease, scope, "/secret"))
            assertFalse(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/secret-sibling"))
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/secret/file"))
            assertNull(database.sharedFolderCacheDao().entry("a", scope.scopeId, child.remoteId))
            assertNull(database.sharedDownloadDao().find(transfer.id))
            assertEquals("CANCELLED", database.transferDao().findById(transfer.id)?.state)
            assertEquals("SUCCEEDED", database.transferDao().findById(completedTransfer.id)?.state)
            assertNull(database.sharedDownloadDao().find(completedTransfer.id))
            assertEquals("CANCELLED", database.transferDao().findById("secret-upload")?.state)
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, child.remoteId))
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, ordinary.remoteId))
            assertFalse(cache.save(lease, staleToken, scope, "/secret", listOf(child)))

            inventory.replace("a", inventory.beginRefresh("a"), emptyList())
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/secret/file"))
            inventory.replace("a", inventory.beginRefresh("a"), listOf(share))
            val renewedLease = lease()
            assertNull(cache.begin(renewedLease, scope, "/secret"))
            assertTrue(
                cache.save(
                    renewedLease,
                    requireNotNull(cache.begin(renewedLease, scope, "/")),
                    scope,
                    "/",
                    listOf(secretFolder, safeFolder),
                ),
            )
            assertFalse(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/secret"))
        }

    @Test fun `encrypted shared root revokes scope and only a fresh plain root snapshot restores it`() =
        runBlocking {
            val lease = lease()
            val folder = entry().copy(remoteId = "secret", path = "/secret", name = "secret", isFolder = true)
            val ordinary = entry().copy(remoteId = "ordinary", path = "/ordinary", name = "ordinary")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/")),
                    scope,
                    "/",
                    listOf(folder, ordinary),
                ),
            )
            val child = entry().copy(parentPath = "/secret", path = "/secret/file")
            val completedChild = child.copy(remoteId = "history", path = "/secret/history")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/secret")),
                    scope,
                    "/secret",
                    listOf(child, completedChild),
                ),
            )
            val fixture = seedSubtreeState(lease, child, completedChild, ordinary)
            val other = scope.copy(scopeId = "other-root")
            val otherEntry = entry().copy(scopeId = other.scopeId, remoteId = "other-file", path = "/other-file")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, other, "/")),
                    other,
                    "/",
                    listOf(otherEntry),
                ),
            )

            val exclusion = SharedFolderListing(emptyList(), setOf("/"))
            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", exclusion))
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/secret/file"))
            assertNull(cache.read(lease, scope, "/"))
            assertNull(cache.read(lease, scope, "/secret"))
            assertFalse(database.sharedFolderCacheDao().hasPage("a", scope.scopeId, "/"))
            assertFalse(database.sharedFolderCacheDao().hasPage("a", scope.scopeId, "/secret"))
            assertNull(database.sharedFolderCacheDao().entry("a", scope.scopeId, child.remoteId))
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, child.remoteId))
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, ordinary.remoteId))
            assertEquals("CANCELLED", database.transferDao().findById(fixture.transfer.id)?.state)
            assertEquals("CANCELLED", database.transferDao().findById("secret-upload")?.state)
            assertEquals("SUCCEEDED", database.transferDao().findById(fixture.completedTransfer.id)?.state)
            assertNull(database.sharedDownloadDao().find(fixture.completedTransfer.id))
            assertEquals(listOf(otherEntry), cache.read(lease, other, "/"))

            val staleProbe = requireNotNull(cache.begin(lease, scope, "/"))
            val currentProbe = requireNotNull(cache.begin(lease, scope, "/"))
            assertTrue(cache.save(lease, currentProbe, scope, "/", exclusion))
            val plain = entry().copy(remoteId = "plain", path = "/plain", name = "plain")
            assertFalse(
                cache.save(
                    lease,
                    staleProbe,
                    scope,
                    "/",
                    SharedFolderListing(listOf(plain), plainCollectionConfirmed = true),
                ),
            )
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/plain"))
            val unmarkedProbe = requireNotNull(cache.begin(lease, scope, "/"))
            assertFalse(cache.save(lease, unmarkedProbe, scope, "/", listOf(plain)))
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/plain"))
            val failedProbe = requireNotNull(cache.begin(lease, scope, "/"))
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking {
                    cache.save(
                        lease,
                        failedProbe,
                        scope,
                        "/",
                        SharedFolderListing(listOf(plain.copy(accountId = "other")), plainCollectionConfirmed = true),
                    )
                }
            }
            assertTrue(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/plain"))

            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/")),
                    scope,
                    "/",
                    SharedFolderListing(listOf(plain), plainCollectionConfirmed = true),
                ),
            )
            assertFalse(database.sharedVaultExclusionDao().denies("a", scope.scopeId, "/plain"))
            assertEquals(listOf(plain), cache.read(lease, scope, "/"))
            assertEquals(listOf(otherEntry), cache.read(lease, other, "/"))
        }

    @Test fun `moved folder revokes descendant state`() =
        runBlocking {
            val lease = lease()
            val folder = entry().copy(remoteId = "folder", path = "/folder", name = "folder", isFolder = true)
            val destination =
                entry().copy(
                    remoteId = "new-parent",
                    path = "/new-parent",
                    name = "new-parent",
                    isFolder = true,
                )
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/")),
                    scope,
                    "/",
                    listOf(folder, destination),
                ),
            )
            val child = entry().copy(parentPath = "/folder", path = "/folder/file")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/folder")),
                    scope,
                    "/folder",
                    listOf(child),
                ),
            )
            val transfer =
                TransferEntity(
                    "removed-folder-download",
                    "a",
                    scope.scopeId,
                    child.remoteId,
                    "DOWNLOAD",
                    null,
                    child.path,
                    child.name,
                    child.mimeType,
                    child.sizeBytes,
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                    expectedETag = child.eTag,
                    locationKind = "SHARED_FOLDER",
                )
            assertEquals(transfer, SharedDownloadStore(database).enqueue(lease, scope, child, transfer))
            database.transferDao().claim(transfer.id, "worker", 1)
            database.sharedLocalFileDao().save(
                SharedLocalFile(
                    "a",
                    scope.scopeId,
                    child.remoteId,
                    child.path,
                    child.sizeBytes,
                    child.eTag,
                    "/private/folder-blob",
                    "b".repeat(64),
                    1,
                    false,
                ),
            )

            val movedFolder = folder.copy(parentPath = "/new-parent", path = "/new-parent/moved", name = "moved")
            assertTrue(
                cache.save(
                    lease,
                    requireNotNull(cache.begin(lease, scope, "/new-parent")),
                    scope,
                    "/new-parent",
                    listOf(movedFolder),
                ),
            )
            assertEquals(listOf(movedFolder), cache.read(lease, scope, "/new-parent"))
            assertEquals(listOf(destination), cache.read(lease, scope, "/"))
            assertNull(cache.read(lease, scope, "/folder"))
            assertEquals("CANCELLED", database.transferDao().findById(transfer.id)?.state)
            assertNull(database.sharedDownloadDao().find(transfer.id))
            assertNull(database.sharedFolderCacheDao().entry("a", scope.scopeId, child.remoteId))
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, child.remoteId))
            assertNull(SharedDownloadStore(database).read(transfer.id))

            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", emptyList()))
            assertEquals(emptyList<SharedFolderEntry>(), cache.read(lease, scope, "/"))
        }

    @Test fun `changed file version invalidates its queued download and verified local copy`() =
        runBlocking {
            val lease = lease()
            val original = entry()
            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(original)))
            val transfer =
                TransferEntity(
                    "changed-version-download",
                    "a",
                    scope.scopeId,
                    original.remoteId,
                    "DOWNLOAD",
                    null,
                    original.path,
                    original.name,
                    original.mimeType,
                    original.sizeBytes,
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                    expectedETag = original.eTag,
                    locationKind = "SHARED_FOLDER",
                )
            assertEquals(transfer, SharedDownloadStore(database).enqueue(lease, scope, original, transfer))
            database.transferDao().claim(transfer.id, "worker", 1)
            database.sharedLocalFileDao().save(
                SharedLocalFile(
                    "a",
                    scope.scopeId,
                    original.remoteId,
                    original.path,
                    original.sizeBytes,
                    original.eTag,
                    "/private/version-blob",
                    "c".repeat(64),
                    1,
                    true,
                ),
            )

            val changed = original.copy(sizeBytes = original.sizeBytes + 1, eTag = "etag-v2")
            assertTrue(cache.save(lease, requireNotNull(cache.begin(lease, scope, "/")), scope, "/", listOf(changed)))
            assertEquals("CANCELLED", database.transferDao().findById(transfer.id)?.state)
            assertNull(database.sharedDownloadDao().find(transfer.id))
            assertNull(database.sharedLocalFileDao().find("a", scope.scopeId, original.remoteId))
            assertNull(SharedDownloadStore(database).read(transfer.id))
            assertEquals(changed, database.sharedFolderCacheDao().entry("a", scope.scopeId, original.remoteId))
        }

    private fun entry() =
        SharedFolderEntry(
            "a",
            scope.scopeId,
            "file",
            "/",
            "/file",
            "file",
            false,
            "text/plain",
            10,
            "etag",
            20,
            10,
        )
}
