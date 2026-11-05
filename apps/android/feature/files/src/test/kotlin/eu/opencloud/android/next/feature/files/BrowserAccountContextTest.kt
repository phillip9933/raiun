package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FileOperationEntity
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

class BrowserAccountContextTest {
    @Test fun `late restore cannot publish after account roundtrip without another Space`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val request = fixture.onMain { fixture.context.restore(binding, "space", "old")!! }
                val job = fixture.scope.launch { fixture.loader.resolve(request) }
                val read = fixture.nextRead()
                fixture.onMain {
                    fixture.context.beginAccount("b")
                    fixture.context.beginAccount("a")
                }
                read.result.complete(folder("old"))
                withTimeout(5000) { job.join() }
                assertTrue(fixture.locations.isEmpty())
                assertEquals(0, fixture.errors)
            }
        }

    @Test fun `late shortcut and its incomplete error cannot beat direct navigation`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val request = fixture.onMain { fixture.context.shortcut(binding, folder("old"))!! }
                val job = fixture.scope.launch { fixture.loader.resolve(request) }
                val read = fixture.nextRead()
                fixture.onMain { fixture.context.userNavigation() }
                read.result.complete(null)
                withTimeout(5000) { job.join() }
                assertTrue(fixture.locations.isEmpty())
                assertEquals(0, fixture.errors)
            }
        }

    @Test fun `new shortcut supersedes a noncooperative initial restore`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val restore = fixture.onMain { fixture.context.restore(binding, "space", "old")!! }
                val oldJob = fixture.scope.launch { fixture.loader.resolve(restore) }
                val oldRead = fixture.nextRead()
                val shortcut = fixture.onMain { fixture.context.shortcut(binding, folder("new"))!! }
                val newJob = fixture.scope.launch { fixture.loader.resolve(shortcut) }
                fixture.nextRead().result.complete(folder("new"))
                withTimeout(5000) { newJob.join() }
                oldRead.result.complete(folder("old"))
                withTimeout(5000) { oldJob.join() }
                assertEquals(listOf(listOf(FolderCrumb("new", "new"))), fixture.locations.map { it.second })
                assertEquals(0, fixture.errors)
            }
        }

    @Test fun `same account restore publishes complete trail only on Main admission`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val request = fixture.onMain { fixture.context.restore(binding, "space", "child")!! }
                val job = fixture.scope.launch { fixture.loader.resolve(request) }
                val child = fixture.nextRead()
                assertEquals("a", child.account)
                assertEquals("space", child.space)
                assertEquals("child", child.id)
                child.result.complete(folder("child", "parent"))
                fixture.nextRead().result.complete(folder("parent"))
                withTimeout(5000) { job.join() }
                assertEquals(
                    listOf(FolderCrumb("parent", "parent"), FolderCrumb("child", "child")),
                    fixture.locations.single().second,
                )
                assertTrue(
                    fixture.locations
                        .single()
                        .first.restoring,
                )
                assertEquals(0, fixture.errors)
            }
        }

    @Test fun `old account collectors cannot publish after roundtrip but current collectors can`() =
        runBlocking {
            Fixture().use { fixture ->
                val old = fixture.onMain { fixture.context.beginAccount("a") }
                fixture.onMain { fixture.context.beginAccount("b") }
                val current = fixture.onMain { fixture.context.beginAccount("a") }
                val published = mutableListOf<String>()
                fixture.context.publishAccount(old) { published += "old operations backups recent spaces" }
                fixture.context.publishAccount(current) { published += "current" }
                assertEquals(listOf("current"), published)
                assertFalse(old == current)
            }
        }

    @Test fun `cancelled noncooperative read cannot publish even with unchanged account`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val request = fixture.onMain { fixture.context.restore(binding, "space", "old")!! }
                val job = fixture.scope.launch { fixture.loader.resolve(request) }
                val read = fixture.nextRead()
                job.cancel()
                read.result.complete(folder("old"))
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertTrue(fixture.locations.isEmpty())
                assertEquals(0, fixture.errors)
            }
        }

    @Test fun `failed initial shortcut permits a new root restore without reviving older restore`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val olderRestore = fixture.onMain { fixture.context.restore(binding, "space", null)!! }
                val shortcut = fixture.onMain { fixture.context.shortcut(binding, folder("missing"))!! }
                assertNull(fixture.onMain { fixture.context.restore(binding, "space", null) })
                val job = fixture.scope.launch { fixture.loader.resolve(shortcut) }
                fixture.nextRead().result.complete(null)
                withTimeout(5000) { job.join() }
                assertEquals(1, fixture.errors)
                val fallback = fixture.onMain { fixture.context.restore(binding, "space", null) }
                assertNotNull(fallback)
                fixture.loader.resolve(olderRestore)
                assertTrue(fixture.locations.isEmpty())
                fixture.loader.resolve(requireNotNull(fallback))
                assertTrue(
                    fixture.locations
                        .single()
                        .second
                        .isEmpty(),
                )
            }
        }

    @Test fun `missing saved folder retains root fallback and unavailable location allows later Space`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val request = fixture.onMain { fixture.context.restore(binding, "space", "missing")!! }
                val job = fixture.scope.launch { fixture.loader.resolve(request) }
                fixture.nextRead().result.complete(null)
                withTimeout(5000) { job.join() }
                assertTrue(
                    fixture.locations
                        .single()
                        .second
                        .isEmpty(),
                )
                assertEquals(0, fixture.errors)
                fixture.onMain {
                    fixture.context.userNavigation()
                    fixture.context.locationUnavailable()
                }
                assertNotNull(fixture.onMain { fixture.context.restore(binding, "later-space", null) })
            }
        }

    @Test fun `failed shortcut read allows initial root recovery with a bounded error`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val shortcut = fixture.onMain { fixture.context.shortcut(binding, folder("unavailable"))!! }
                val job = fixture.scope.launch { fixture.loader.resolve(shortcut) }
                fixture.nextRead().result.completeExceptionally(IllegalStateException("synthetic private details"))
                withTimeout(5000) { job.join() }
                assertEquals(1, fixture.errors)
                val root = fixture.onMain { fixture.context.restore(binding, "space", null) }
                fixture.loader.resolve(requireNotNull(root))
                assertTrue(
                    fixture.locations
                        .single()
                        .second
                        .isEmpty(),
                )
            }
        }

    @Test fun `account reset removes previous route and action metadata while retaining preferences`() {
        val resource = folder("private")
        val backup =
            FolderBackupEntity(
                "backup",
                "a",
                "space",
                "content://test/source",
                "Source",
                "/dest",
                "ALL",
                true,
                false,
                false,
            )
        val operation =
            FileOperationEntity(
                "operation",
                "a",
                "space",
                "space",
                "private",
                null,
                null,
                "/",
                "/",
                "/private",
                "/copy",
                "etag",
                true,
            )
        val before =
            FileBrowserUiState(
                spaces = listOf(space("space", "personal")),
                spaceId = "space",
                currentFolderId = "private",
                folderTrail = listOf(FolderCrumb("private", "private")),
                backups = listOf(backup),
                operations = listOf(operation),
                clipboard = resource,
                clipboardItems = listOf(resource),
                moving = true,
                selectedIds = setOf("private"),
                selectedResources = listOf(resource),
                resources = listOf(resource),
                layout = BrowserLayout.TILES,
                temporaryCopyRetentionHours = 48,
                exporting = true,
                exportStatus = "old-account export",
                remoteSearchSupported = true,
                isRemoteSearchLoading = true,
                remoteSearchError = "old-account search failure",
            )
        val after = before.forAccountLoad()
        assertNull(after.spaceId)
        assertNull(after.currentFolderId)
        assertNull(after.clipboard)
        assertNull(after.exportStatus)
        assertFalse(after.exporting)
        assertFalse(after.remoteSearchSupported)
        assertFalse(after.isRemoteSearchLoading)
        assertNull(after.remoteSearchError)
        assertFalse(after.moving)
        assertTrue(after.spaces.isEmpty())
        assertTrue(after.folderTrail.isEmpty())
        assertTrue(after.backups.isEmpty())
        assertTrue(after.operations.isEmpty())
        assertTrue(after.clipboardItems.isEmpty())
        assertTrue(after.resources.isEmpty())
        assertTrue(after.selectedResources.isEmpty())
        assertTrue(after.selectedIds.isEmpty())
        assertEquals(BrowserLayout.TILES, after.layout)
        assertEquals(48, after.temporaryCopyRetentionHours)
    }

    @Test fun `Space selection rejects unavailable old ID and keeps active Space authoritative`() {
        val personal = space("personal", "personal")
        val shared = space("shared", "project")
        val spaces = listOf(personal, shared)
        assertEquals(personal, admittedBrowserSpace(spaces, "removed", "old-account-space"))
        assertEquals(shared, admittedBrowserSpace(spaces, "shared", "personal"))
        assertEquals(shared, admittedBrowserSpace(spaces, null, "shared"))
        assertNull(admittedBrowserSpace(emptyList(), "shared", "shared"))
    }

    @Test fun `resource entry admission rejects foreign and unloaded accounts`() =
        runBlocking {
            Fixture().use { fixture ->
                val source = folder("remembered-dialog-resource")
                fixture.onMain {
                    assertNull(fixture.context.admitResource(source))
                    val accountA = fixture.context.beginAccount("a")
                    assertEquals(accountA, fixture.context.admitResource(source))
                    val accountB = fixture.context.beginAccount("b")
                    assertNull(fixture.context.admitResource(source))
                    assertEquals(accountB, fixture.context.admitResource(source.copy(accountId = "b")))
                }
            }
        }

    @Test fun `account roundtrip advances presentation revision and clears prior data`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.onMain {
                    val firstA = fixture.context.beginAccount("a")
                    val firstState = FileBrowserUiState(layout = BrowserLayout.TILES).forAccountLoad(firstA)
                    val accountB = fixture.context.beginAccount("b")
                    val secondState = firstState.copy(actionResource = folder("old-details")).forAccountLoad(accountB)
                    val returnedA = fixture.context.beginAccount("a")
                    val returnedState = secondState.forAccountLoad(returnedA)
                    assertEquals(firstA.accountRevision, firstState.accountRevision)
                    assertTrue(secondState.accountRevision > firstState.accountRevision)
                    assertTrue(returnedState.accountRevision > secondState.accountRevision)
                    assertNull(secondState.actionResource)
                    assertNull(returnedState.actionResource)
                    assertEquals(BrowserLayout.TILES, returnedState.layout)
                }
            }
        }

    private class Fixture : AutoCloseable {
        private val admissionThread = AtomicReference<Thread>()
        private val dispatcher =
            Executors
                .newSingleThreadExecutor { task ->
                    Thread(task, "browser-admission").also { admissionThread.set(it) }
                }.asCoroutineDispatcher()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val context = BrowserAccountContext(dispatcher)
        val locations = CopyOnWriteArrayList<Pair<BrowserLocationRequest, List<FolderCrumb>>>()
        var errors = 0
        private val reads = Channel<Read>(Channel.UNLIMITED)
        val loader =
            BrowserLocationLoader(
                context,
                read = { account, space, id ->
                    val request = Read(account, space, id)
                    reads.send(request)
                    // Deliberately ignores cancellation while the underlying read finishes.
                    withContext(NonCancellable) { request.result.await() }
                },
                publish = { request, trail ->
                    assertSame(admissionThread.get(), Thread.currentThread())
                    locations += request to trail
                },
                incomplete = {
                    assertSame(admissionThread.get(), Thread.currentThread())
                    errors++
                },
            )

        suspend fun nextRead(): Read = withTimeout(5000) { reads.receive() }

        suspend fun <T> onMain(action: () -> T): T = withContext(dispatcher) { action() }

        override fun close() {
            scope.cancel()
            dispatcher.close()
        }
    }

    private class Read(
        val account: String,
        val space: String,
        val id: String,
    ) {
        val result = CompletableDeferred<ResourceEntity?>()
    }

    private companion object {
        fun space(
            id: String,
            type: String,
        ) = SpaceEntity("a", id, id, type, null, null, "root", null, null, null)

        fun folder(
            id: String,
            parent: String? = null,
        ) = ResourceEntity("a", "space", id, parent, "/$id", id, ResourceKind.FOLDER, null, 0, null, 0, 0)
    }
}
