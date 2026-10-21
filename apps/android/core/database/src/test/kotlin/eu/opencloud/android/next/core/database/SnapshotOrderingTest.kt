package eu.opencloud.android.next.core.database

import androidx.room.Room
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SnapshotOrderingTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val resource =
        ResourceEntity("a", "s", "file", null, "/file", "file", ResourceKind.FILE, null, 5, "v1", 0, 0)

    @Before fun setUp() {
        database =
            Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
    }

    @After fun tearDown() = database.close()

    @Test fun `vault folder cleanup uses exact subtree boundaries and rejects late child snapshots`() =
        runTest {
            val vault = resource.copy(remoteId = "vault", path = "/a_%", name = "a_%", kind = ResourceKind.FOLDER)
            val neighbor =
                resource.copy(
                    remoteId = "neighbor",
                    path = "/a_%more",
                    name = "a_%more",
                    kind = ResourceKind.FOLDER,
                )
            val child = resource.copy(path = "/a_%/file", parentId = "vault", offlinePinned = true)
            store.replaceFolderSnapshot("a", "s", null, listOf(vault, neighbor))
            database.resourceDao().insert(child)
            database.offlineTraversalDao().insertRun(OfflineRunEntity("vault-run", "a", "s", "vault"))
            database.offlineTraversalDao().insertRun(OfflineRunEntity("child-run", "a", "s", "file"))
            database.openHelper.writableDatabase.execSQL("INSERT INTO pending_pins VALUES ('a', 's', '/a_%/new', 0)")
            database.openHelper.writableDatabase.execSQL(
                "INSERT INTO pending_pins VALUES ('a', 's', '/a_%more/new', 0)",
            )
            val old = store.beginFolderSnapshot("a", "s", "vault")
            assertTrue(
                store.replaceDiscoveredFolderSnapshot("a", "s", null, FolderSnapshot(listOf(neighbor), setOf("/a_%"))),
            )
            assertEquals(null, store.resource("a", "s", "vault"))
            assertEquals(null, store.resource("a", "s", "file"))
            assertEquals(neighbor, store.resource("a", "s", "neighbor"))
            assertEquals("CANCELLED", database.offlineTraversalDao().forRoot("a", "s", "vault")?.state)
            assertEquals("CANCELLED", database.offlineTraversalDao().forRoot("a", "s", "file")?.state)
            assertFalse(database.pendingPinDao().selected("a", "s", "/a_%/new"))
            assertTrue(database.pendingPinDao().selected("a", "s", "/a_%more/new"))
            assertFalse(store.replaceFolderSnapshot("a", "s", "vault", listOf(child), old))
        }

    @Test fun `vault cleanup cannot target another folder or a visible snapshot item`() =
        runTest {
            val folder =
                resource.copy(
                    remoteId = "parent",
                    path = "/parent",
                    name = "parent",
                    kind = ResourceKind.FOLDER,
                )
            database.resourceDao().insert(folder)
            database.resourceDao().insert(resource)
            listOf("/file", "/parent/../file", "/parent/", "/parent/a/b").forEach { excluded ->
                org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                    kotlinx.coroutines.runBlocking {
                        store.replaceDiscoveredFolderSnapshot(
                            "a",
                            "s",
                            "parent",
                            FolderSnapshot(emptyList(), setOf(excluded)),
                        )
                    }
                }
                assertEquals(resource, store.resource("a", "s", "file"))
            }
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking {
                    store.replaceDiscoveredFolderSnapshot(
                        "a",
                        "s",
                        null,
                        FolderSnapshot(listOf(resource), setOf("/file")),
                    )
                }
            }
            assertEquals(resource, store.resource("a", "s", "file"))
        }

    @Test fun `explicit vault exclusion drops cached rows and pins while preserving other scopes`() =
        runTest {
            val space =
                SpaceEntity("a", "s", "Space", "project", null, null, "root", "https://cloud.example/dav/s", null, null)
            store.replaceRemoteSpaces("a", listOf(space, space.copy(driveId = "other")))
            database.resourceDao().insert(resource.copy(offlinePinned = true, isFavorite = true))
            database.resourceDao().insert(resource.copy(spaceId = "other"))
            database.resourceDao().insert(resource.copy(accountId = "b"))
            database.offlineTraversalDao().insertRun(OfflineRunEntity("run", "a", "s", "file"))
            database.offlineTraversalDao().insertRun(OfflineRunEntity("other-run", "a", "other", "file"))
            database.openHelper.writableDatabase.execSQL("INSERT INTO pending_pins VALUES ('a', 's', '/file', 0)")
            database.openHelper.writableDatabase.execSQL("INSERT INTO pending_pins VALUES ('b', 's', '/file', 0)")
            val oldFolder = store.beginFolderSnapshot("a", "s", null)
            assertTrue(
                store.replaceRemoteSpaces("a", listOf(space.copy(driveId = "other")), excludedVaultIds = setOf("s")),
            )
            assertEquals(null, store.resource("a", "s", "file"))
            assertEquals(resource.copy(spaceId = "other"), store.resource("a", "other", "file"))
            assertEquals(resource.copy(accountId = "b"), store.resource("b", "s", "file"))
            assertTrue(requireNotNull(store.space("a", "s")).isDisabled)
            assertEquals("CANCELLED", database.offlineTraversalDao().forRoot("a", "s", "file")?.state)
            assertEquals("ACTIVE", database.offlineTraversalDao().forRoot("a", "other", "file")?.state)
            assertFalse(database.pendingPinDao().selected("a", "s", "/file"))
            assertTrue(database.pendingPinDao().selected("b", "s", "/file"))
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), oldFolder))
        }

    @Test fun `stale vault evidence cannot revoke a newer ordinary drive snapshot`() =
        runTest {
            val space =
                SpaceEntity("a", "s", "Space", "project", null, null, "root", "https://cloud.example/dav/s", null, null)
            val old = store.beginSnapshot("a")
            val current = store.beginSnapshot("a")
            assertTrue(store.replaceRemoteSpaces("a", listOf(space), current))
            database.resourceDao().insert(resource)
            assertFalse(store.replaceRemoteSpaces("a", emptyList(), old, setOf("s")))
            assertEquals(resource, store.resource("a", "s", "file"))
            assertFalse(requireNotNull(store.space("a", "s")).isDisabled)
        }

    @Test fun `confirmed folder rename rebases descendants and rejects stale child discovery`() =
        runTest {
            val folder = resource.copy(remoteId = "folder", kind = ResourceKind.FOLDER, path = "/old", name = "old")
            val child = resource.copy(parentId = "folder", path = "/old/file", offlinePinned = true)
            store.replaceFolderSnapshot("a", "s", null, listOf(folder))
            database.resourceDao().insert(child)
            val delayed = store.beginSnapshot("a")
            store.replaceFolderSnapshot("a", "s", null, listOf(folder.copy(path = "/new", name = "new")))
            val moved = requireNotNull(store.resource("a", "s", "file"))
            assertEquals("/new/file", moved.path)
            assertTrue(moved.offlinePinned)
            assertFalse(store.replaceFolderSnapshot("a", "s", "folder", listOf(child), delayed))
        }

    @Test fun `delayed response cannot replace a newer snapshot from another store instance`() =
        runTest {
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val old =
                async {
                    val token = store.beginSnapshot("a")
                    started.complete(Unit)
                    release.await()
                    store.replaceFolderSnapshot("a", "s", null, emptyList(), token)
                }
            started.await()
            val otherStore = FileBrowserStore(database)
            val newer = otherStore.beginSnapshot("a")
            assertTrue(otherStore.replaceFolderSnapshot("a", "s", null, listOf(resource), newer))
            release.complete(Unit)
            assertFalse(old.await())
            assertEquals(listOf(resource), store.children("a", "s", null))
            assertFalse(otherStore.replaceFolderSnapshot("a", "s", null, emptyList(), newer))
        }

    @Test fun `favorite confirmation and deletion invalidate in flight snapshots`() =
        runTest {
            store.replaceFolderSnapshot("a", "s", null, listOf(resource))
            val beforeFavorite = store.beginSnapshot("a")
            store.setFavorite(resource, true)
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), beforeFavorite))
            assertTrue(requireNotNull(store.resource("a", "s", "file")).isFavorite)
            val beforeDelete = store.beginSnapshot("a")
            store.delete("a", "s", "file")
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), beforeDelete))
            assertTrue(store.children("a", "s", null).isEmpty())
        }

    @Test fun `account deletion cannot be undone by discovery and other accounts remain independent`() =
        runTest {
            val a = store.beginSnapshot("a")
            val b = store.beginSnapshot("b")
            store.removeAccount("a")
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), a))
            assertTrue(store.replaceFolderSnapshot("b", "s", null, listOf(resource.copy(accountId = "b")), b))
        }

    @Test fun `missing spaces retain cached resources and pins`() =
        runTest {
            seedActiveScope()
            val space =
                SpaceEntity("a", "s", "Space", "project", null, null, "root", "https://cloud.example/dav/s", null, null)
            store.replaceRemoteSpaces("a", listOf(space))
            store.replaceFolderSnapshot("a", "s", null, listOf(resource.copy(offlinePinned = true)))
            store.setOfflinePinned(resource, true)
            val token = store.beginSnapshot("a")
            assertTrue(store.replaceRemoteSpaces("a", emptyList(), token))
            assertTrue(requireNotNull(store.space("a", "s")).isDisabled)
            assertTrue(requireNotNull(store.resource("a", "s", "file")).offlinePinned)
        }

    @Test fun `folder deletion treats wildcard characters literally`() =
        runTest {
            val first = resource.copy(remoteId = "first", name = "a_%", path = "/a_%", kind = ResourceKind.FOLDER)
            val second = resource.copy(remoteId = "second", name = "axb", path = "/axb", kind = ResourceKind.FOLDER)
            val child = resource.copy(remoteId = "child", parentId = "second", path = "/axb/file")
            store.replaceFolderSnapshot("a", "s", null, listOf(first, second))
            store.replaceFolderSnapshot("a", "s", "second", listOf(child))
            store.delete("a", "s", "first")
            assertEquals(child, store.resource("a", "s", "child"))
        }

    @Test fun `sibling refreshes publish independently and tokens remain single use`() =
        runTest {
            val first = store.beginFolderSnapshot("a", "s", "one")
            val second = FileBrowserStore(database).beginFolderSnapshot("a", "s", "two")
            assertTrue(store.replaceFolderSnapshot("a", "s", "two", emptyList(), second))
            assertTrue(store.replaceFolderSnapshot("a", "s", "one", emptyList(), first))
            assertFalse(store.replaceFolderSnapshot("a", "s", "one", emptyList(), first))
        }

    @Test fun `scoped tokens reject wrong destinations and older same folder refreshes`() =
        runTest {
            val old = store.beginFolderSnapshot("a", "s", null)
            val current = store.beginFolderSnapshot("a", "s", null)
            assertFalse(store.replaceFolderSnapshot("a", "s", null, emptyList(), old))
            assertFalse(store.replaceFolderSnapshot("a", "other", null, emptyList(), current))
            assertFalse(store.replaceFolderSnapshot("a", "s", "other", emptyList(), current))
            assertFalse(store.replaceRemoteSpaces("a", emptyList(), current))
            assertTrue(store.replaceFolderSnapshot("a", "s", null, listOf(resource), current))
        }

    @Test fun `confirmed mutations and account removal invalidate scoped refreshes`() =
        runTest {
            store.replaceFolderSnapshot("a", "s", null, listOf(resource))
            val beforeFavorite = store.beginFolderSnapshot("a", "s", null)
            store.setFavorite(resource, true)
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), beforeFavorite))
            val beforeRemoval = store.beginFolderSnapshot("a", "s", null)
            val otherAccount = store.beginFolderSnapshot("b", "s", null)
            store.removeAccount("a")
            assertFalse(store.replaceFolderSnapshot("a", "s", null, listOf(resource), beforeRemoval))
            assertTrue(store.replaceFolderSnapshot("b", "s", null, emptyList(), otherAccount))
        }

    @Test fun `parent removal invalidates in flight descendant listing`() =
        runTest {
            val folder = resource.copy(remoteId = "folder", kind = ResourceKind.FOLDER)
            store.replaceFolderSnapshot("a", "s", null, listOf(folder))
            val child = store.beginFolderSnapshot("a", "s", "folder")
            val parent = store.beginFolderSnapshot("a", "s", null)
            assertTrue(store.replaceFolderSnapshot("a", "s", null, emptyList(), parent))
            assertFalse(store.replaceFolderSnapshot("a", "s", "folder", emptyList(), child))
        }

    @Test fun `abandoned folder leases are bounded and evicted responses fail closed`() {
        val versions = SnapshotVersions()
        val scope = FolderSnapshotScope("s", "old")
        val old = versions.beginFolder("a", scope)
        repeat(1024) { versions.beginFolder("a", FolderSnapshotScope("s", it.toString())) }
        assertFalse(versions.accept("a", old, scope))
        val newest = versions.beginFolder("a", scope)
        assertTrue(versions.accept("a", newest, scope))
        assertFalse(versions.accept("a", newest, scope))
    }

    @Test fun `favorites reconcile cached folders atomically without altering pins or other accounts`() =
        runTest {
            seedActiveScope()
            val first = resource.copy(parentId = "folder", isFavorite = true)
            val second = first.copy(remoteId = "second", path = "/second", name = "second")
            store.replaceFolderSnapshot("a", "s", "folder", listOf(first, second))
            store.replaceFolderSnapshot("b", "s", "folder", listOf(first.copy(accountId = "b")))
            store.setOfflinePinned(first, true)
            val token = store.beginSnapshot("a")
            assertTrue(store.replaceFavoriteSnapshot("a", mapOf("s" to setOf("second", "unseen")), token))
            assertFalse(requireNotNull(store.resource("a", "s", "file")).isFavorite)
            assertTrue(requireNotNull(store.resource("a", "s", "file")).offlinePinned)
            assertTrue(requireNotNull(store.resource("a", "s", "second")).isFavorite)
            assertTrue(requireNotNull(store.resource("b", "s", "file")).isFavorite)
            assertEquals(null, store.resource("a", "s", "unseen"))
            val stale = store.beginSnapshot("a")
            store.setFavorite(first, true)
            assertFalse(store.replaceFavoriteSnapshot("a", mapOf("s" to emptySet()), stale))
            assertTrue(requireNotNull(store.resource("a", "s", "file")).isFavorite)
        }

    @Test fun `conflicting folder names preserve the previous snapshot`() =
        runTest {
            store.replaceFolderSnapshot("a", "s", null, listOf(resource))
            val token = store.beginFolderSnapshot("a", "s", null)
            try {
                store.replaceFolderSnapshot(
                    "a",
                    "s",
                    null,
                    listOf(resource, resource.copy(remoteId = "other", path = "/other")),
                    token,
                )
                org.junit.Assert.fail("Duplicate names must not silently replace cached identities")
            } catch (_: IllegalArgumentException) {
                assertEquals(listOf(resource), store.children("a", "s", null))
            }
        }

    @Test fun `local cache metadata survives an accepted remote refresh`() =
        runTest {
            seedActiveScope()
            store.replaceFolderSnapshot("a", "s", null, listOf(resource))
            val token = store.beginSnapshot("a")
            store.setOfflinePinned(requireNotNull(store.resource("a", "s", "file")), true)
            store.updateLocalCopy("a", "s", "file", "/cache/file")
            assertTrue(store.replaceFolderSnapshot("a", "s", null, listOf(resource), token))
            val cached = requireNotNull(store.resource("a", "s", "file"))
            assertTrue(cached.offlinePinned)
            assertEquals("/cache/file", cached.localPath)
        }

    @Test fun `remote content change invalidates cached bytes without clearing pin`() =
        runTest {
            database.resourceDao().insert(
                resource.copy(offlinePinned = true, hasLocalCopy = true, localPath = "/cache/old"),
            )
            store.replaceFolderSnapshot("a", "s", null, listOf(resource.copy(eTag = "v2")))
            val refreshed = requireNotNull(store.resource("a", "s", "file"))
            assertTrue(refreshed.offlinePinned)
            assertFalse(refreshed.hasLocalCopy)
            assertEquals(null, refreshed.localPath)
        }

    @Test fun `cancelled or superseded download cannot publish cache`() =
        runTest {
            database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity(
                    "a",
                    "s",
                    "Space",
                    "project",
                    null,
                    null,
                    "root",
                    "https://cloud.example/dav/s",
                    null,
                    null,
                ),
            )
            database.resourceDao().insert(resource)
            val transfer =
                TransferEntity(
                    "download",
                    "a",
                    "s",
                    "file",
                    "DOWNLOAD",
                    null,
                    "/file",
                    "file",
                    null,
                    5,
                    state = "RUNNING",
                    workId = "worker",
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                )
            database.transferDao().insert(transfer)
            assertTrue(store.publishDownload(transfer, resource, "/cache/valid"))
            database.transferDao().update(transfer.copy(state = "CANCELLED"))
            assertFalse(store.publishDownload(transfer, resource, "/cache/cancelled"))
            database.transferDao().update(transfer)
            store.replaceFolderSnapshot("a", "s", null, listOf(resource.copy(eTag = "v2")))
            assertFalse(store.publishDownload(transfer, resource, "/cache/stale"))
        }

    private suspend fun seedActiveScope() {
        database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
        database.spaceDao().upsertAll(
            listOf(
                SpaceEntity(
                    "a",
                    "s",
                    "Space",
                    "project",
                    null,
                    null,
                    "root",
                    "https://cloud.example/dav/s",
                    null,
                    null,
                ),
            ),
        )
    }
}
