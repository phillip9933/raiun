package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.database.SharedDownloadStore
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteResource
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.network.SharedRemoteItem
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SharedDownloadResolverTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val inventory = IncomingShareStore(database)
    private val discovery =
        IncomingShareRepository(inventory) {
            listOf(IncomingSharedItem("share", SharedRemoteItem("root", "Folder", folder = JsonObject(emptyMap()))))
        }
    private var root = "https://example.test/dav/authorized-root/"
    private var allowed = true
    private var resolutions = 0
    private val access =
        IncomingShareAccessRepository(inventory) { _, _ ->
            resolutions++
            if (allowed) {
                SharedFolderResolution.Resolved(
                    "server-drive",
                    "root",
                    root,
                    SharedFolderAccess(setOf("libre.graph/driveItem/children/read")),
                )
            } else {
                SharedFolderResolution.Unavailable
            }
        }
    private var item = RemoteResource("file", "/photo.jpg", "photo.jpg", false, "image/jpeg", 12, "\"v1\"", 0, 0)
    private var listing: suspend () -> List<RemoteResource> = { listOf(item) }
    private val paths = mutableListOf<String>()
    private val browser =
        SharedFolderBrowser(access, SharedFolderPageCache(SharedFolderCacheStore(database))) { _, _, path ->
            paths.add(path)
            listing()
        }
    private val resolver = SharedDownloadResolver(browser)

    @Test fun `queue restores through fresh resolution and rejects cancelled or replaced work`() =
        runBlocking {
            val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
            val request = resolver.capture(browser.open("a", "share"), "file")
            val source = resolver.prepare(request)
            val transfer = queue.enqueue(source, "transfer", false, 1)
            assertEquals(request, queue.restore(transfer.id)?.request)
            listing = {
                database.transferDao().cancel(transfer.id)
                listOf(item)
            }
            assertPrecondition { queue.restore(transfer.id) ?: error("Expected stale rejection") }
            assertEquals(null, queue.restore(transfer.id))
        }

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            discovery.refresh("a")
            Unit
        }

    @Test fun retryRevalidatesAndReplacesOwnership() =
        runBlocking {
            val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
            val source = resolver.prepare(resolver.capture(browser.open("a", "share"), "file"))
            val queued = queue.enqueue(source, "retry", true, 1)
            val failed = queued.copy(state = "FAILED", workId = "old", bytesTransferred = 3, errorCode = "CONNECTIVITY")
            database.transferDao().update(failed)
            val retry = checkNotNull(queue.retry(failed, "new", 3))
            assertEquals("QUEUED", retry.state)
            assertEquals("new", retry.workId)
            assertEquals(0L, retry.bytesTransferred)
            assertTrue(retry.offlinePin)
            assertEquals(null, retry.errorCode)
            assertEquals(null, queue.retry(failed, "stale", 4))
            assertEquals(null, database.transferDao().claim("retry", "old", 5))
            assertEquals("new", database.transferDao().claim("retry", "new", 5)?.workId)
        }

    @Test fun retryDoesNotDuplicateNewDownload() =
        runBlocking {
            val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
            val source = resolver.prepare(resolver.capture(browser.open("a", "share"), "file"))
            val failed = queue.enqueue(source, "old", false, 1).copy(state = "FAILED", workId = "old-worker")
            database.transferDao().update(failed)
            val active = queue.enqueue(source, "new", true, 2)
            assertEquals(null, queue.retry(failed, "retry-worker", 3))
            assertEquals(failed, database.transferDao().findById("old"))
            assertEquals(active, database.transferDao().findById("new"))
        }

    @Test fun retryRejectsChangedFile() =
        runBlocking {
            val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
            val source = resolver.prepare(resolver.capture(browser.open("a", "share"), "file"))
            val failed = queue.enqueue(source, "retry", false, 1).copy(state = "FAILED", workId = "old")
            database.transferDao().update(failed)
            item = item.copy(eTag = "\"v2\"")
            assertPrecondition { queue.retry(failed, "new", 2) ?: error("Expected rejection") }
            assertEquals(failed, database.transferDao().findById("retry"))
        }

    @Test fun retryObservesConcurrentCancellation() =
        runBlocking {
            val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
            val source = resolver.prepare(resolver.capture(browser.open("a", "share"), "file"))
            val failed = queue.enqueue(source, "retry", false, 1).copy(state = "FAILED", workId = "old")
            database.transferDao().update(failed)
            listing = {
                database.transferDao().cancel("retry")
                listOf(item)
            }
            assertEquals(null, queue.retry(failed, "new", 2))
            assertEquals("CANCELLED", database.transferDao().findById("retry")?.state)
        }

    @After fun close() {
        database.close()
    }

    @Test fun `serialized selection resolves fresh metadata with bounded correctly encoded URL`() =
        runBlocking {
            item = item.copy(path = "/photo #?%2F.jpg")
            val request = resolver.capture(browser.open("a", "share"), "file")
            val serialized = Json.encodeToString(request)
            assertFalse(serialized.contains("https://"))
            val restored = Json.decodeFromString<SharedDownloadRequest>(serialized)
            val source = resolver.prepare(restored)
            assertEquals(2, resolutions)
            assertEquals("server-drive", source.location.serverDriveId)
            assertEquals(request.scopeId, source.location.scopeId)
            assertEquals("https://example.test/dav/authorized-root/photo%20%23%3F%252F.jpg", source.url)
            assertEquals(12L, source.expectation.length)
            assertEquals("\"v1\"", source.expectation.strongETag)
            assertTrue(resolver.isCurrent(source))
        }

    @Test fun `nested file checks its parent inside the original root`() =
        runBlocking {
            val location = browser.open("a", "share").location
            item = item.copy(path = "/Photos/photo.jpg")
            val request = resolver.capture(browser.list(location, "/Photos"), "file")
            paths.clear()
            val source = resolver.prepare(request)
            assertEquals(listOf("/Photos"), paths)
            assertEquals("https://example.test/dav/authorized-root/Photos/photo.jpg", source.url)
        }

    @Test fun `root replacement cannot retarget saved selection even with identical file metadata`() =
        runBlocking {
            val request = resolver.capture(browser.open("a", "share"), "file")
            paths.clear()
            root = "https://example.test/dav/replacement/"
            assertPrecondition { resolver.prepare(request) }
            assertTrue(paths.isEmpty())
        }

    @Test fun `changed version size path identity kind or missing file rejects selection`() =
        runBlocking {
            val original = item
            val request = resolver.capture(browser.open("a", "share"), "file")
            val changed =
                listOf(
                    original.copy(eTag = "\"v2\""),
                    original.copy(eTag = null),
                    original.copy(size = 13),
                    original.copy(path = "/renamed.jpg"),
                    original.copy(id = "replacement"),
                    original.copy(folder = true),
                )
            changed.forEach {
                item = it
                assertPrecondition { resolver.prepare(request) }
            }
            listing = { emptyList() }
            assertPrecondition { resolver.prepare(request) }
        }

    @Test fun `damaged requests are rejected before any server resolution`() =
        runBlocking {
            val request = resolver.capture(browser.open("a", "share"), "file")
            val count = resolutions
            listOf("/", "relative", "/../outside", "/folder//file", "/folder/./file", "/bad\\file").forEach {
                assertPrecondition { resolver.prepare(request.copy(file = request.file.copy(path = it))) }
            }
            assertPrecondition { resolver.prepare(request.copy(accountId = "")) }
            assertPrecondition { resolver.prepare(request.copy(file = request.file.copy(sizeBytes = -1))) }
            assertEquals(count, resolutions)
        }

    @Test fun `revocation cancellation and refreshed inventory do not yield reusable access`() =
        runBlocking {
            val page = browser.open("a", "share")
            val request = resolver.capture(page, "file")
            allowed = false
            val denied = assertThrows(OpenCloudException::class.java) { runBlocking { resolver.prepare(request) } }
            assertEquals(OpenCloudError.AccessDenied, denied.error)
            allowed = true
            listing = { throw CancellationException() }
            assertThrows(CancellationException::class.java) { runBlocking { resolver.prepare(request) } }
            listing = { listOf(item) }
            val source = resolver.prepare(request)
            discovery.refresh("a")
            assertFalse(resolver.isCurrent(source))
            assertPrecondition { resolver.capture(page, "file") }
            assertTrue(resolver.isCurrent(resolver.prepare(request)))
        }

    @Test fun `folders unknown items and unknown lengths cannot be captured`() =
        runBlocking {
            assertPrecondition { resolver.capture(browser.open("a", "share"), "missing") }
            item = item.copy(folder = true)
            assertPrecondition { resolver.capture(browser.open("a", "share"), "file") }
            item = item.copy(folder = false, size = -1)
            assertPrecondition { resolver.capture(browser.open("a", "share"), "file") }
        }

    private fun assertPrecondition(action: suspend () -> Any) {
        val error = assertThrows(OpenCloudException::class.java) { runBlocking { action() } }
        assertEquals(OpenCloudError.PreconditionFailed, error.error)
    }
}
