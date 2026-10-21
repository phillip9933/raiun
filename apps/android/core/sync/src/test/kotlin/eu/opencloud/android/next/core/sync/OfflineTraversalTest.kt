package eu.opencloud.android.next.core.sync

import androidx.room.Room
import androidx.room.RoomDatabase
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.OfflineTraversalStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
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
class OfflineTraversalTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var files: FileBrowserStore
    private lateinit var queue: OfflineTraversalStore
    private val root =
        ResourceEntity("a", "s", "0-root", null, "/root", "root", ResourceKind.FOLDER, null, 0, null, 0, 0)

    @Before fun setUp() {
        context.deleteDatabase(NAME)
        open()
    }

    private fun open() {
        database =
            Room
                .databaseBuilder(context, FileBrowserDatabase::class.java, NAME)
                .setJournalMode(RoomDatabase.JournalMode.TRUNCATE)
                .build()
        files = FileBrowserStore(database)
        queue = OfflineTraversalStore(database)
    }

    @After fun tearDown() {
        database.close()
        context.deleteDatabase(NAME)
    }

    @Test fun `reopened queue resumes its child cursor without rediscovering completed directory`() =
        runTest {
            seed(258)
            val run = queue.start(root)
            assertEquals(run, queue.start(root))
            var refreshes = 0
            val downloads = mutableListOf<String>()
            val first = OfflineTraversal(queue, files, { refreshes++ }, { downloads += it.remoteId })
            assertTrue(first.step(run.id, budget = 2))
            assertEquals(129, queue.dao.count(run.id))
            database.close()
            open()
            val resumed = OfflineTraversal(queue, files, { refreshes++ }, { downloads += it.remoteId })
            var passes = 0
            while (resumed.step(run.id)) {
                check(++passes < 100)
            }
            assertEquals(1, refreshes)
            assertEquals(258, downloads.size)
            assertEquals(258, downloads.distinct().size)
            assertEquals("COMPLETE", queue.dao.run(run.id)?.state)
            assertFalse(resumed.step(run.id))
            val nextRun = queue.start(root)
            assertTrue(nextRun.id != run.id)
            assertEquals(1, queue.dao.count(nextRun.id))
            assertEquals(0, queue.dao.count(run.id))
        }

    @Test fun `cancelled discovery keeps pending intent and can resume`() =
        runTest {
            seed(0)
            val run = queue.start(root)
            try {
                OfflineTraversal(queue, files, { throw CancellationException() }, {}).step(run.id)
                org.junit.Assert.fail("Cancellation must escape")
            } catch (_: CancellationException) {
                assertEquals("PENDING", queue.dao.next(run.id)?.state)
                assertEquals("ACTIVE", queue.dao.run(run.id)?.state)
            }
            assertFalse(OfflineTraversal(queue, files, {}, {}).step(run.id))
            assertEquals("COMPLETE", queue.dao.run(run.id)?.state)
        }

    @Test fun `account deletion removes durable traversal and all nodes`() =
        runTest {
            seed(1)
            val run = queue.start(root)
            files.removeAccount("a")
            assertEquals(null, queue.dao.run(run.id))
            assertEquals(0, queue.dao.count(run.id))
            assertFalse(OfflineTraversal(queue, files, {}, {}).step(run.id))
            try {
                queue.start(root)
                org.junit.Assert.fail("A stale root must not recreate an account's traversal")
            } catch (_: IllegalArgumentException) {
                assertTrue(queue.dao.active().isEmpty())
            }
        }

    @Test fun `pinned descendants do not create overlapping traversal roots`() =
        runTest {
            seed(2)
            files.children("a", "s", root.remoteId).forEach { files.setOfflinePinned(it, true) }
            assertEquals(listOf(root.remoteId), queue.dao.pinnedRoots().map { it.remoteId })
        }

    @Test fun `pass yields at its time budget and unpin prevents more work`() =
        runTest {
            seed(1)
            val run = queue.start(root)
            var clock = 0L
            var downloads = 0
            val traversal = OfflineTraversal(queue, files, { clock = 20_001 }, { downloads++ }, { clock })
            assertTrue(traversal.step(run.id))
            assertEquals("DISCOVERED", queue.dao.next(run.id)?.state)
            assertEquals(0, downloads)
            files.setOfflinePinned(root, false)
            assertFalse(traversal.step(run.id))
            assertEquals("CANCELLED", queue.dao.run(run.id)?.state)
        }

    @Test fun `traversal inherits selection without creating independent child pins`() =
        runTest {
            seed(2)
            val child = files.children("a", "s", root.remoteId).first()
            files.setOfflinePinned(child, true)
            val run = queue.start(root)
            val downloads = mutableListOf<String>()
            assertFalse(OfflineTraversal(queue, files, {}, { downloads += it.remoteId }).step(run.id))
            assertEquals(2, downloads.size)
            files.setOfflinePinned(root, false)
            assertEquals(listOf(child.remoteId), queue.dao.pinnedRoots().map { it.remoteId })
            assertEquals(listOf(child.remoteId), files.offlinePinnedResources().map { it.remoteId })
        }

    @Test fun `unpin during discovery is not undone when discovery returns`() =
        runTest {
            seed(1)
            val run = queue.start(root)
            var downloads = 0
            val traversal = OfflineTraversal(queue, files, { files.setOfflinePinned(root, false) }, { downloads++ })
            assertFalse(traversal.step(run.id))
            assertEquals(0, downloads)
            assertEquals("CANCELLED", queue.dao.run(run.id)?.state)
            assertTrue(files.offlinePinnedResources().isEmpty())
        }

    @Test fun `cache completion preserves current pin selection`() =
        runTest {
            seed(1)
            val child = files.children("a", "s", root.remoteId).single()
            files.setOfflinePinned(child, true)
            files.updateLocalCopy("a", "s", child.remoteId, "/cache/file")
            assertTrue(requireNotNull(files.resource("a", "s", child.remoteId)).offlinePinned)
            files.setOfflinePinned(child, false)
            files.updateLocalCopy("a", "s", child.remoteId, "/cache/file")
            val cached = requireNotNull(files.resource("a", "s", child.remoteId))
            assertFalse(cached.offlinePinned)
            assertTrue(cached.hasLocalCopy)
        }

    @Test fun `space root suppresses descendants only in its own account and space`() =
        runTest {
            val spaceRoot = root.copy(path = "/", offlinePinned = true)
            database.resourceDao().upsert(spaceRoot)
            val child = root.copy(remoteId = "child", parentId = root.remoteId, offlinePinned = true)
            database.resourceDao().upsert(child)
            database.resourceDao().upsert(child.copy(accountId = "b"))
            database.resourceDao().upsert(child.copy(spaceId = "other"))
            assertEquals(
                setOf(Triple("a", "s", root.remoteId), Triple("b", "s", "child"), Triple("a", "other", "child")),
                queue.dao
                    .pinnedRoots()
                    .map { Triple(it.accountId, it.spaceId, it.remoteId) }
                    .toSet(),
            )
        }

    @Test fun `ten thousand children expand in bounded pages without duplicate nodes`() =
        runTest {
            seed(10_000)
            val run = queue.start(root)
            var node = requireNotNull(queue.dao.next(run.id))
            queue.dao.updateNode(node.copy(state = "DISCOVERED"))
            var pages = 0
            while (node.resourceId == root.remoteId) {
                val before = queue.dao.count(run.id)
                queue.expand(run, node.copy(state = "DISCOVERED"))
                assertTrue(queue.dao.count(run.id) - before in 0..128)
                check(++pages <= 80)
                node = requireNotNull(queue.dao.next(run.id))
            }
            assertEquals(80, pages)
            assertEquals(10_001, queue.dao.count(run.id))
        }

    @Test fun `parent supersedes child and unpin restores child ownership`() =
        runTest {
            seed(1)
            files.setOfflinePinned(root, false)
            val child = files.children("a", "s", root.remoteId).single()
            files.setOfflinePinned(child, true)
            val childRun = queue.start(child)
            files.setOfflinePinned(root, true)
            val parentRun = queue.start(root)
            assertEquals("CANCELLED", queue.dao.run(childRun.id)?.state)
            assertEquals(listOf(parentRun), queue.dao.active())
            assertEquals(parentRun, queue.start(child))
            assertFalse(OfflineTraversal(queue, files, {}, { error("Superseded run must stop") }).step(childRun.id))
            files.setOfflinePinned(root, false)
            val resumed = queue.start(child)
            assertEquals(child.remoteId, resumed.rootId)
            assertTrue(resumed.id != childRun.id)
            assertEquals(listOf(resumed), queue.dao.active())
        }

    @Test fun `parent selection during child discovery stops expansion`() =
        runTest {
            seed(0)
            val child =
                root.copy(
                    remoteId = "child",
                    parentId = root.remoteId,
                    path = "/root/child",
                    offlinePinned = true,
                )
            database.resourceDao().upsert(child)
            files.setOfflinePinned(root, false)
            val childRun = queue.start(child)
            val traversal =
                OfflineTraversal(queue, files, {
                    files.setOfflinePinned(root, true)
                    queue.start(root)
                }, { error("Superseded run must not download") })
            assertFalse(traversal.step(childRun.id))
            assertEquals("CANCELLED", queue.dao.run(childRun.id)?.state)
            assertEquals("PENDING", queue.dao.next(childRun.id)?.state)
            assertEquals(
                root.remoteId,
                queue.dao
                    .active()
                    .single()
                    .rootId,
            )
        }

    @Test fun `covering root uses literal scoped paths and the outermost selected ancestor`() =
        runTest {
            val parent = root.copy(path = "/r_%", offlinePinned = true)
            val child = parent.copy(remoteId = "child", path = "/r_%/child")
            val leaf = child.copy(remoteId = "leaf", path = "/r_%/child/leaf")
            val unrelated = child.copy(remoteId = "unrelated", path = "/r_%-other/child")
            listOf(parent, child, leaf, unrelated, child.copy(accountId = "b"), child.copy(spaceId = "other")).forEach {
                database.resourceDao().upsert(it)
            }
            val otherRuns = listOf(queue.start(unrelated), queue.start(child.copy(accountId = "b")))
            val spaceRun = queue.start(child.copy(spaceId = "other"))
            val run = queue.start(leaf)
            assertEquals(parent.remoteId, run.rootId)
            assertEquals(run, queue.start(child))
            assertEquals((otherRuns + spaceRun + run).toSet(), queue.dao.active().toSet())
        }

    @Test fun `recovery promotes child and leaves completed work alone`() =
        runTest {
            seed(1)
            files.setOfflinePinned(root, false)
            val child = files.children("a", "s", root.remoteId).single()
            files.setOfflinePinned(child, true)
            val childRun = queue.start(child)
            files.setOfflinePinned(root, true)
            database.close()
            open()
            val recovered = requireNotNull(queue.reconcile(childRun.id))
            assertEquals(root.remoteId, recovered.rootId)
            assertEquals("CANCELLED", queue.dao.run(childRun.id)?.state)
            assertEquals(null, queue.reconcile(childRun.id))
            assertEquals(recovered, queue.reconcile(recovered.id))
            queue.dao.finish(recovered.id, "COMPLETE")
            assertEquals(null, queue.reconcile(recovered.id))
            assertTrue(queue.dao.active().isEmpty())
        }

    @Test fun `root discovery and recovery use bounded resumable pages`() =
        runTest {
            seed(100)
            files.setOfflinePinned(root, false)
            files.children("a", "s", root.remoteId).forEach { files.setOfflinePinned(it, true) }
            val scheduled = mutableListOf<String>()
            var cursor: OfflineMaintenanceCursor? = OfflineMaintenanceCursor(null, null, null)
            var pages = 0
            do {
                val before = scheduled.size
                cursor = OfflineMaintenance(queue) { scheduled += it }.discover(requireNotNull(cursor))
                assertTrue(scheduled.size - before in 1..32)
                pages++
            } while (cursor != null)
            assertEquals(4, pages)
            assertEquals(100, scheduled.distinct().size)
            val recovered = mutableListOf<String>()
            var after: String? = null
            do {
                val before = recovered.size
                after = OfflineMaintenance(queue) { recovered += it }.recover(after)
                assertTrue(recovered.size - before in 1..32)
            } while (after != null)
            assertEquals(scheduled.toSet(), recovered.toSet())
            assertEquals(100, recovered.size)
        }

    @Test fun `unpin during root dispatch skips the stale selection`() =
        runTest {
            seed(2)
            files.setOfflinePinned(root, false)
            val children = files.children("a", "s", root.remoteId)
            children.forEach { files.setOfflinePinned(it, true) }
            val scheduled = mutableListOf<String>()
            OfflineMaintenance(queue) {
                scheduled += it
                files.setOfflinePinned(children.last(), false)
            }.discover(OfflineMaintenanceCursor(null, null, null))
            assertEquals(1, scheduled.size)
            assertEquals(1, queue.dao.active().size)
        }

    private suspend fun seed(count: Int) {
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
        files.replaceFolderSnapshot("a", "s", null, listOf(root))
        files.setOfflinePinned(root, true)
        val children =
            (1..count).map { index ->
                val id = "file-%04d".format(index)
                root.copy(
                    remoteId = id,
                    parentId = root.remoteId,
                    path = "/root/$id",
                    name = id,
                    kind = ResourceKind.FILE,
                )
            }
        files.replaceFolderSnapshot("a", "s", root.remoteId, children)
    }

    companion object {
        private const val NAME = "offline-traversal-test.db"
    }
}
