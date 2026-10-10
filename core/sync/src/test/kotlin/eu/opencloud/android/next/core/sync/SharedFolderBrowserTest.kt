package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteFolderSnapshot
import eu.opencloud.android.next.core.network.RemoteResource
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.network.SharedRemoteItem
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
@Suppress("LargeClass") // Shared browser and queue scenarios reuse one revocable share fixture.
class SharedFolderBrowserTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `shared backup creates nested folders only under a freshly resolved scoped parent`() =
        runBlocking {
            val children = mutableMapOf<String, MutableList<RemoteResource>>()
            val browser = SharedFolderBrowser(access) { _, _, path -> children[path].orEmpty() }
            val root = browser.open("a", "one").location
            val base = SharedFolderRequest("a", "one", root.scopeId, root.rootItemId, "/")
            val resolver =
                SharedUploadDestinationResolver(browser) { page, remote ->
                    val path =
                        when (remote) {
                            root.rootItemId -> "/"
                            "dated" -> "/2026"
                            "camera" -> "/2026/Camera"
                            else -> error("Unexpected folder")
                        }
                    SharedFolderResolution.Resolved(
                        page.location.serverDriveId,
                        remote,
                        page.location.rootWebDavUrl.trimEnd('/') + (if (path == "/") "/" else "$path/"),
                        SharedFolderAccess(
                            setOf("libre.graph/driveItem/upload/create", "libre.graph/driveItem/children/create"),
                        ),
                    )
                }
            val created = mutableListOf<String>()
            var backupEnabled = true
            val folders =
                SharedBackupCollections(browser, resolver) { parent, name, checkCurrent ->
                    if (name == "Blocked") backupEnabled = false
                    checkCurrent()
                    created += "${parent.request.path}/$name"
                    val path = if (parent.request.path == "/") "/$name" else "${parent.request.path}/$name"
                    val id = if (name == "2026") "dated" else "camera"
                    children.getOrPut(parent.request.path) { mutableListOf() } +=
                        RemoteResource(id, path, name, true, null, 0, null, 0, 0)
                }
            assertEquals("/2026/Camera", folders.ensure(base, "/2026/Camera").path)
            assertEquals(listOf("//2026", "/2026/Camera"), created)
            assertEquals("/2026/Camera", folders.ensure(base, "/2026/Camera").path)
            assertEquals(2, created.size)
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { folders.ensure(base, "/Blocked") { require(backupEnabled) } }
            }
            assertEquals(2, created.size)
            permitted = false
            assertThrows(
                OpenCloudException::class.java,
            ) { runBlocking { folders.ensure(base, "/2026/Camera/Revoked") } }
            assertEquals(2, created.size)
        }

    @Test fun `shared backup refuses vault excluded child before mkdir`() =
        runBlocking {
            val browser =
                SharedFolderBrowser(
                    access = access,
                    fetchSnapshot = { _, _, _ -> RemoteFolderSnapshot(emptyList(), setOf("/vault")) },
                    fetch = { _, _, _ -> error("No fallback listing") },
                )
            val root = browser.open("a", "one").location
            val base = SharedFolderRequest("a", "one", root.scopeId, root.rootItemId, "/")
            val resolver =
                SharedUploadDestinationResolver(browser) { page, remote ->
                    SharedFolderResolution.Resolved(
                        page.location.serverDriveId,
                        remote,
                        page.location.rootWebDavUrl,
                        SharedFolderAccess(
                            setOf("libre.graph/driveItem/upload/create", "libre.graph/driveItem/children/create"),
                        ),
                    )
                }
            var created = false
            val folders = SharedBackupCollections(browser, resolver) { _, _, _ -> created = true }
            val failure =
                assertThrows(OpenCloudException::class.java) { runBlocking { folders.ensure(base, "/vault") } }
            assertEquals(OpenCloudError.Unsupported, failure.error)
            assertFalse(created)
        }

    @Test fun `shared backup queue rejects edited configuration without ordinary drive fallback`() =
        runBlocking {
            val browser =
                SharedFolderBrowser(
                    access,
                    SharedFolderPageCache(SharedFolderCacheStore(database)),
                ) { _, _, _ -> emptyList() }
            val root = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", root.scopeId, root.rootItemId, "/")
            val resolver =
                SharedUploadDestinationResolver(browser) { page, remote ->
                    SharedFolderResolution.Resolved(
                        page.location.serverDriveId,
                        remote,
                        page.location.rootWebDavUrl,
                        SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                    )
                }
            val backup =
                FolderBackupEntity(
                    id = "backup",
                    accountId = "a",
                    spaceId = root.scopeId,
                    sourceTreeUri = "content://source/tree",
                    destinationPath = "/",
                    mediaType = "ALL",
                    wifiOnly = false,
                    chargingOnly = false,
                    deleteAfterUpload = false,
                    destinationKind = "SHARED_FOLDER",
                    sharedShareId = "one",
                    sharedFolderId = root.rootItemId,
                )
            database.folderBackupDao().upsert(backup.copy(enabled = false))
            val transfer =
                TransferEntity(
                    id = "backup-upload",
                    accountId = "a",
                    spaceId = root.scopeId,
                    resourceId = root.rootItemId,
                    direction = "UPLOAD",
                    sourceUri = "content://source/file",
                    destinationPath = "/file",
                    displayName = "file",
                    mimeType = "text/plain",
                    bytesTotal = 1,
                    locationKind = "SHARED_FOLDER",
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                )
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { IncomingFolderUploadQueue(database, resolver).enqueue(request, transfer, backup) }
            }
            assertNull(database.transferDao().findById(transfer.id))
        }

    @Test fun incomingUploadUsesConditionalCreateAndVerifiesRemoteBytes() =
        runBlocking {
            verifyIncomingUpload("hello", pending = false)
        }

    @Test fun incomingUploadDoesNotAcceptSuccessfulHttpWithWrongBytes() =
        runBlocking {
            verifyIncomingUpload("other", pending = false)
        }

    @Test fun incomingUploadResumesVerificationWithoutReplacingRemoteFile() =
        runBlocking {
            verifyIncomingUpload("hello", pending = true)
        }

    private suspend fun verifyIncomingUpload(
        remoteBody: String,
        pending: Boolean,
    ) {
        val browser =
            SharedFolderBrowser(
                access,
                SharedFolderPageCache(SharedFolderCacheStore(database)),
            ) { _, _, _ -> emptyList() }
        val location = browser.open("a", "one").location
        val request = SharedFolderRequest("a", "one", location.scopeId, location.rootItemId, "/")
        val resolver =
            SharedUploadDestinationResolver(browser) { page, remote ->
                SharedFolderResolution.Resolved(
                    page.location.serverDriveId,
                    remote,
                    page.location.rootWebDavUrl,
                    SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                )
            }
        val queue = IncomingFolderUploadQueue(database, resolver)
        val transfer =
            TransferEntity(
                id = "upload",
                accountId = "a",
                spaceId = location.scopeId,
                resourceId = location.rootItemId,
                direction = "UPLOAD",
                sourceUri = "content://source/file",
                destinationPath = "/file",
                displayName = "file",
                mimeType = "text/plain",
                bytesTotal = 5,
                locationKind = "SHARED_FOLDER",
                createdAtEpochMillis = 1,
                updatedAtEpochMillis = 1,
                verificationPending = pending,
            )
        queue.enqueue(request, transfer)
        val running = requireNotNull(database.transferDao().claim("upload", "worker", 2))
        val staged = temporary.newFile().apply { writeText("hello") }
        MockWebServer().use { server ->
            server.start()
            if (!pending) {
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(201))
            }
            val verificationAttempts = if (remoteBody == "hello") 1 else 6
            repeat(verificationAttempts) {
                server.enqueue(MockResponse().setResponseCode(405))
                server.enqueue(MockResponse().setBody(remoteBody).setHeader("ETag", "\"v1\""))
            }
            val client =
                TransferClient(
                    OkHttpClient
                        .Builder()
                        .addInterceptor { chain ->
                            chain.proceed(
                                chain
                                    .request()
                                    .newBuilder()
                                    .url(server.url(chain.request().url.encodedPath))
                                    .build(),
                            )
                        }.build(),
                )
            val executor = IncomingFolderUploadExecutor(queue, FileBrowserStore(database), client)
            if (remoteBody == "hello") {
                executor.execute(running, staged, "Bearer test") { _, _ -> }
                assertEquals("SUCCEEDED", database.transferDao().findById("upload")?.state)
            } else {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { executor.execute(running, staged, "Bearer test") { _, _ -> } }
                }
                assertEquals("RUNNING", database.transferDao().findById("upload")?.state)
            }
            if (!pending) {
                assertEquals("HEAD", server.takeRequest().method)
                val put = server.takeRequest()
                assertEquals("PUT", put.method)
                assertEquals("*", put.getHeader("If-None-Match"))
                assertEquals("/dav/one/file", put.path)
                assertEquals("hello", put.body.readUtf8())
            }
            repeat(verificationAttempts) {
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("GET", server.takeRequest().method)
            }
            assertEquals(verificationAttempts * 2 + if (pending) 0 else 2, server.requestCount)
        }
    }

    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val store = IncomingShareStore(database)
    private val one = item("one")
    private val two = item("two")
    private val discovery = IncomingShareRepository(store) { listOf(one, two) }
    private var rootSuffix = ""
    private var permitted = true
    private val access =
        IncomingShareAccessRepository(store) { _, share ->
            SharedFolderResolution.Resolved(
                "same-drive",
                share.remoteItem.id,
                "https://example.test/dav/${share.id}$rootSuffix/",
                SharedFolderAccess(if (permitted) setOf("libre.graph/driveItem/children/read") else emptySet()),
            )
        }

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            discovery.refresh("a")
            Unit
        }

    @After fun close() {
        database.close()
    }

    @Test fun sharedUploadQueueJoinsDuplicatesAndCompletesOnlyCurrentOwnedWork() =
        runBlocking {
            val browser =
                SharedFolderBrowser(
                    access,
                    SharedFolderPageCache(SharedFolderCacheStore(database)),
                ) { _, _, _ -> emptyList() }
            val location = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", location.scopeId, location.rootItemId, "/")
            val resolver =
                SharedUploadDestinationResolver(browser) { page, remote ->
                    SharedFolderResolution.Resolved(
                        page.location.serverDriveId,
                        remote,
                        page.location.rootWebDavUrl,
                        SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                    )
                }
            val queue = IncomingFolderUploadQueue(database, resolver)
            val transfer =
                TransferEntity(
                    id = "upload",
                    accountId = "a",
                    spaceId = location.scopeId,
                    resourceId = location.rootItemId,
                    direction = "UPLOAD",
                    sourceUri = "content://source/file",
                    destinationPath = "/file",
                    displayName = "file",
                    mimeType = "text/plain",
                    bytesTotal = 5,
                    locationKind = "SHARED_FOLDER",
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                )
            assertEquals(transfer, queue.enqueue(request, transfer))
            assertEquals(transfer, queue.enqueue(request, transfer.copy(id = "duplicate")))
            val running = requireNotNull(database.transferDao().claim("upload", "worker", 2))
            val destination = queue.prepare(running)
            assertFalse(queue.complete(running.copy(workId = "old-worker"), destination, "verified", 3))
            assertEquals(true, queue.complete(running, destination, "verified", 3))
            assertEquals("SUCCEEDED", database.transferDao().findById("upload")?.state)
            assertFalse(queue.complete(running, destination, "verified", 4))
        }

    @Test fun sharedUploadQueueRejectsRemovedScopesAndUnsafeReplacement() =
        runBlocking {
            val browser =
                SharedFolderBrowser(
                    access,
                    SharedFolderPageCache(SharedFolderCacheStore(database)),
                ) { _, _, _ -> emptyList() }
            val location = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", location.scopeId, location.rootItemId, "/")
            val resolver =
                SharedUploadDestinationResolver(browser) { page, remote ->
                    SharedFolderResolution.Resolved(
                        page.location.serverDriveId,
                        remote,
                        page.location.rootWebDavUrl,
                        SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                    )
                }
            val queue = IncomingFolderUploadQueue(database, resolver)
            val transfer =
                TransferEntity(
                    id = "upload",
                    accountId = "a",
                    spaceId = location.scopeId,
                    resourceId = location.rootItemId,
                    direction = "UPLOAD",
                    sourceUri = "content://source/file",
                    destinationPath = "/file",
                    displayName = "file",
                    mimeType = "text/plain",
                    bytesTotal = 5,
                    locationKind = "SHARED_FOLDER",
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                )
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { queue.enqueue(request, transfer.copy(overwrite = true)) }
            }
            queue.enqueue(request, transfer)
            database.accountDao().delete("a")
            assertThrows(OpenCloudException::class.java) { runBlocking { queue.prepare(transfer) } }
            Unit
        }

    @Test fun uploadDestinationRequiresExactTargetRightsAndContainedAddress() =
        runBlocking {
            val child = RemoteResource("child", "/Photos", "Photos", true, null, 0, "v1", 0, 0)
            val browser = SharedFolderBrowser(access) { _, _, path -> if (path == "/") listOf(child) else emptyList() }
            val root = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", root.scopeId, "child", "/Photos")
            val target =
                SharedFolderResolution.Resolved(
                    root.serverDriveId,
                    "child",
                    "${root.rootWebDavUrl}Photos/",
                    SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                )
            val resolver =
                SharedUploadDestinationResolver(browser) { _, remote ->
                    assertEquals("child", remote)
                    target
                }
            assertEquals(target.webDavUrl, resolver.prepare(request).webDavUrl)
            val invalid =
                listOf(
                    target.copy(access = SharedFolderAccess(emptySet())),
                    target.copy(itemId = "other"),
                    target.copy(driveId = "other-drive"),
                    target.copy(webDavUrl = "https://example.test/dav/outside/"),
                    target.copy(webDavUrl = "https://other.test/dav/one/Photos/"),
                )
            invalid.forEach { response ->
                val rejected = SharedUploadDestinationResolver(browser) { _, _ -> response }
                assertThrows(OpenCloudException::class.java) { runBlocking { rejected.prepare(request) } }
            }
        }

    @Test fun uploadDestinationRejectsRefreshDuringResolutionAndPreservesCancellation() =
        runBlocking {
            val browser = SharedFolderBrowser(access) { _, _, _ -> emptyList() }
            val root = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", root.scopeId, root.rootItemId, "/")
            val stale =
                SharedUploadDestinationResolver(browser) { _, _ ->
                    store.beginRefresh("a")
                    SharedFolderResolution.Resolved(
                        root.serverDriveId,
                        root.rootItemId,
                        root.rootWebDavUrl,
                        SharedFolderAccess(setOf("libre.graph/driveItem/upload/create")),
                    )
                }
            assertThrows(OpenCloudException::class.java) { runBlocking { stale.prepare(request) } }
            discovery.refresh("a")
            val cancelled = SharedUploadDestinationResolver(browser) { _, _ -> throw CancellationException() }
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.prepare(request) } }
            Unit
        }

    @Test fun rootCatalogPreservesDistinctSharesAndReportsUnresolvedOnes() =
        runBlocking {
            val browser = SharedFolderBrowser(access) { _, _, _ -> emptyList() }
            val roots =
                SharedRootDiscovery(store, discovery::refresh) { share ->
                    browser.open(share.accountId, share.id).location
                }
            val catalog = roots.discover("a")
            assertEquals(2, catalog.roots.size)
            assertNotEquals(catalog.roots[0].scopeId, catalog.roots[1].scopeId)
            val partial =
                SharedRootDiscovery(store, discovery::refresh) { share ->
                    if (share.id == "one") browser.open("a", "one").location else null
                }.discover("a")
            assertEquals(listOf("one"), partial.roots.map { it.shareId })
            assertEquals(listOf("two"), partial.unavailable.map { it.id })
            assertFalse(roots.isCurrent(catalog))
        }

    @Test fun rootCatalogRejectsMidResolutionRefreshAndPreservesCancellation() =
        runBlocking<Unit> {
            val stale =
                SharedRootDiscovery(store, discovery::refresh) {
                    store.beginRefresh("a")
                    null
                }
            assertThrows(OpenCloudException::class.java) { runBlocking { stale.discover("a") } }
            val cancelled = SharedRootDiscovery(store, discovery::refresh) { throw CancellationException() }
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.discover("a") } }
            val failed = SharedRootDiscovery(store, { false }) { error("Must not resolve failed inventory") }
            assertThrows(OpenCloudException::class.java) { runBlocking { failed.discover("a") } }
        }

    @Test fun emptyRootCatalogStillHasRevocableAccountEvidence() =
        runBlocking {
            val empty = IncomingShareRepository(store) { emptyList() }
            val roots = SharedRootDiscovery(store, empty::refresh) { error("Empty inventory") }
            val catalog = roots.discover("a")
            assertEquals(0, catalog.roots.size)
            assertEquals(0, catalog.unavailable.size)
            store.beginRefresh("a")
            assertFalse(roots.isCurrent(catalog))
            assertNull(store.snapshot("a"))
        }

    @Test fun folderSelectionRechecksParentIdentityBeforeListing() =
        runBlocking {
            val folder = RemoteResource("folder", "/Photos", "Photos", true, null, 0, null, 0, 0)
            var selected = folder
            val paths = mutableListOf<String>()
            val browser =
                SharedFolderBrowser(access) { _, _, path ->
                    paths.add(path)
                    if (path == "/") listOf(selected) else emptyList()
                }
            val root = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", root.scopeId, "folder", "/Photos")
            paths.clear()
            assertEquals("/Photos", browser.openFolder(request).path)
            assertEquals(listOf("/", "/Photos"), paths)
            selected = folder.copy(id = "replacement")
            paths.clear()
            assertThrows(OpenCloudException::class.java) { runBlocking { browser.openFolder(request) } }
            assertEquals(listOf("/"), paths)
        }

    @Test fun folderSelectionRejectsChangedRootAndNonFolder() =
        runBlocking {
            val file = RemoteResource("file", "/file", "file", false, null, 1, null, 0, 0)
            val browser = SharedFolderBrowser(access) { _, _, _ -> listOf(file) }
            val root = browser.open("a", "one").location
            val request = SharedFolderRequest("a", "one", root.scopeId, root.rootItemId, "/")
            assertEquals("/", browser.openFolder(request).path)
            assertThrows(OpenCloudException::class.java) {
                runBlocking { browser.openFolder(request.copy(remoteId = "wrong")) }
            }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { browser.openFolder(request.copy(remoteId = "file", path = "/file")) }
            }
            rootSuffix = "-changed"
            assertThrows(OpenCloudException::class.java) { runBlocking { browser.openFolder(request) } }
            Unit
        }

    @Test fun `overlapping listings persist only the newest page in the isolated cache`() =
        runBlocking {
            val started = CompletableDeferred<Unit>()
            val finish = CompletableDeferred<Unit>()
            val cache = SharedFolderPageCache(SharedFolderCacheStore(database))
            val child = RemoteResource("file", "/file", "file", false, "text/plain", 10, "etag", 20, 10)
            var reads = 0
            val browser =
                SharedFolderBrowser(access, cache) { _, _, _ ->
                    if (reads++ == 0) {
                        started.complete(Unit)
                        finish.await()
                        listOf(child)
                    } else {
                        listOf(child.copy(size = 22))
                    }
                }
            val old = async { runCatching { browser.open("a", "one") } }
            started.await()
            val fresh = browser.open("a", "one")
            finish.complete(Unit)
            assertEquals(OpenCloudError.PreconditionFailed, (old.await().exceptionOrNull() as OpenCloudException).error)
            val saved = database.sharedFolderCacheDao().children("a", fresh.location.scopeId, "/").single()
            assertEquals(22L, saved.sizeBytes)
            assertEquals(
                "same-drive",
                database.sharedFolderCacheDao().scope("a", fresh.location.scopeId)?.serverDriveId,
            )
        }

    @Test fun `shared folder browser preserves complete listing exclusion evidence`() =
        runBlocking {
            val ordinary = RemoteResource("plain", "/plain", "plain", false, "text/plain", 3, "v1", 0, 0)
            var cleanupScheduled = false
            val browser =
                SharedFolderBrowser(
                    access = access,
                    cache = SharedFolderPageCache(SharedFolderCacheStore(database)) { cleanupScheduled = true },
                    fetchSnapshot = { _, _, _ -> RemoteFolderSnapshot(listOf(ordinary), setOf("/vault")) },
                    fetch = { _, _, _ -> error("snapshot fetch should be used") },
                )
            val page = browser.open("a", "one")
            assertEquals(setOf("/vault"), page.excludedVaultPaths)
            assertTrue(cleanupScheduled)
            assertEquals(
                listOf(ordinary.id),
                database.sharedFolderCacheDao().children("a", page.location.scopeId, "/").map { it.remoteId },
            )
            assertTrue(database.sharedVaultExclusionDao().denies("a", page.location.scopeId, "/vault/child"))
            assertFalse(database.sharedVaultExclusionDao().denies("a", page.location.scopeId, "/vault-copy"))
        }

    @Test fun `encrypted requested root is saved and rejected before returning a page`() =
        runBlocking {
            var cleanupScheduled = false
            val cache = SharedFolderCacheStore(database)
            val browser =
                SharedFolderBrowser(
                    access = access,
                    cache = SharedFolderPageCache(cache) { cleanupScheduled = true },
                    fetchSnapshot = { _, _, _ -> RemoteFolderSnapshot(emptyList(), setOf("/")) },
                    fetch = { _, _, _ -> error("snapshot fetch should be used") },
                )
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { browser.open("a", "one") } }
            assertEquals(OpenCloudError.Unsupported, failure.error)
            assertTrue(cleanupScheduled)
            val checked = requireNotNull(access.resolve("a", "one"))
            val location = SharedFolderLocation.from(checked)
            val scopeId = location.scopeId
            assertTrue(database.sharedVaultExclusionDao().denies("a", scopeId, "/child"))
            assertFalse(database.sharedFolderCacheDao().hasPage("a", scopeId, "/"))
            assertNull(cache.read(checked.lease, location.binding(), "/"))

            val plain = RemoteResource("plain", "/plain", "plain", false, "text/plain", 3, "v1", 0, 0)
            val unmarkedBrowser =
                SharedFolderBrowser(
                    access = access,
                    cache = SharedFolderPageCache(cache),
                    fetchSnapshot = { _, _, _ -> RemoteFolderSnapshot(listOf(plain), emptySet()) },
                    fetch = { _, _, _ -> error("snapshot fetch should be used") },
                )
            val stale =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { unmarkedBrowser.open("a", "one") }
                }
            assertEquals(OpenCloudError.PreconditionFailed, stale.error)
            assertTrue(database.sharedVaultExclusionDao().denies("a", scopeId, "/plain"))

            val recoveredBrowser =
                SharedFolderBrowser(
                    access = access,
                    cache = SharedFolderPageCache(cache),
                    fetchSnapshot = { _, _, _ ->
                        RemoteFolderSnapshot(listOf(plain), emptySet(), plainCollectionConfirmed = true)
                    },
                    fetch = { _, _, _ -> error("snapshot fetch should be used") },
                )
            assertEquals(listOf(plain), recoveredBrowser.open("a", "one").items)
            assertFalse(database.sharedVaultExclusionDao().denies("a", scopeId, "/plain"))
        }

    @Test fun `shared roots on one server drive have distinct stable local scopes`() =
        runBlocking {
            val browser = SharedFolderBrowser(access) { _, _, _ -> emptyList() }
            val first = browser.open("a", "one").location
            val second = browser.open("a", "two").location
            assertEquals(first.serverDriveId, second.serverDriveId)
            assertNotEquals(first.scopeId, second.scopeId)
            assertNotEquals(first.serverDriveId, first.scopeId)
            assertEquals("remote-one", first.rootItemId)
            assertEquals("https://example.test/dav/one/", first.rootWebDavUrl)
            database.accountDao().upsert(AccountEntity("b", "https://example.test", "u", "User", "BASIC", false))
            discovery.refresh("b")
            assertNotEquals(first.scopeId, browser.open("b", "one").location.scopeId)
            IncomingShareRepository(store) { listOf(one.copy(name = "Renamed"), two) }.refresh("a")
            assertEquals(first.scopeId, browser.open("a", "one").location.scopeId)
        }

    @Test fun `root relative navigation stays within its scope and cannot navigate above root`() =
        runBlocking {
            val requests = mutableListOf<String>()
            val browser =
                SharedFolderBrowser(access) { _, location, path ->
                    requests += location.rootWebDavUrl + "|" + path
                    emptyList()
                }
            val location = browser.open("a", "one").location
            assertNull(location.parentPath("/"))
            assertEquals("/", location.parentPath("/Photos"))
            assertEquals("/Photos", location.parentPath("/Photos/June"))
            browser.list(location, "/Photos/June")
            val invalidPaths =
                listOf("/../outside", "/Photos/../../outside", "/Photos\\outside", "//outside", "relative")
            for (path in invalidPaths) {
                assertThrows(OpenCloudException::class.java) { runBlocking { browser.list(location, path) } }
            }
            assertEquals(
                listOf("https://example.test/dav/one/|/", "https://example.test/dav/one/|/Photos/June"),
                requests,
            )
        }

    @Test fun `changed shared root cannot reuse an existing navigation location`() =
        runBlocking {
            var reads = 0
            val browser =
                SharedFolderBrowser(access) { _, _, _ ->
                    reads++
                    emptyList()
                }
            val location = browser.open("a", "one").location
            rootSuffix = "-replacement"
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { browser.list(location, "/Photos") }
                }
            assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            assertEquals(1, reads)
            assertNotEquals(location.scopeId, browser.open("a", "one").location.scopeId)
        }

    @Test fun `fresh denied access prevents listing even after a previous successful open`() =
        runBlocking {
            var reads = 0
            val browser =
                SharedFolderBrowser(access) { _, _, _ ->
                    reads++
                    emptyList()
                }
            val location = browser.open("a", "one").location
            permitted = false
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { browser.list(location, "/") } }
            assertEquals(OpenCloudError.AccessDenied, failure.error)
            assertEquals(1, reads)
        }

    @Test fun `refresh during listing discards the page and cancellation remains cancellation`() =
        runBlocking {
            val browser =
                SharedFolderBrowser(access) { _, _, _ ->
                    discovery.refresh("a")
                    emptyList()
                }
            assertThrows(OpenCloudException::class.java) { runBlocking { browser.open("a", "one") } }
            val cancelled = SharedFolderBrowser(access) { _, _, _ -> throw CancellationException() }
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.open("a", "one") } }
            val reader = SharedFolderBrowser(access) { _, _, _ -> emptyList() }
            val page = reader.open("a", "one")
            discovery.refresh("a")
            assertFalse(reader.isCurrent(page))
        }

    @Test fun `non-child and duplicate listing items are rejected instead of published`() =
        runBlocking {
            val child = RemoteResource("id", "/photo.jpg", "photo.jpg", false, "image/jpeg", 10, "etag", 0, 0)
            val cases =
                listOf(
                    listOf(child.copy(path = "/other/photo.jpg")),
                    listOf(child, child),
                    listOf(child.copy(path = "/../outside")),
                    listOf(child.copy(id = "")),
                )
            cases.forEach { items ->
                val browser = SharedFolderBrowser(access) { _, _, _ -> items }
                assertThrows(OpenCloudException::class.java) { runBlocking { browser.open("a", "one") } }
            }
            val valid = SharedFolderBrowser(access) { _, _, _ -> listOf(child) }
            assertEquals(listOf(child), valid.open("a", "one").items)
        }

    @Test fun folderDetailsUseValidatedIdentityAndFreshAccessInsteadOfDiscoveryClaims() =
        runBlocking {
            val browser = SharedFolderBrowser(access) { _, _, _ -> emptyList() }
            val root = browser.open("a", "one")
            val metadata =
                one.copy(
                    effectiveActions = setOf("libre.graph/driveItem/upload/create"),
                    parentReference =
                        eu.opencloud.android.next.core.network
                            .SharedParentReference("recipient"),
                    size = 123,
                )
            val details = describeIncomingFolder(root, metadata, root.location.rootItemId)
            assertEquals("https://example.test/f/remote-one", details.permanentLink)
            assertTrue(details.access.canBrowse)
            assertFalse(details.access.canUpload)
            assertTrue(details.canChangeVisibility)
            val child = browser.list(root.location, "/Child")
            val childDetails = describeIncomingFolder(child, metadata, "child-id")
            assertEquals("https://example.test/f/child-id", childDetails.permanentLink)
            assertFalse(childDetails.canChangeVisibility)
            assertNull(childDetails.size)
        }

    private fun item(id: String) =
        IncomingSharedItem(
            id,
            SharedRemoteItem("remote-$id", "Folder", folder = JsonObject(emptyMap())),
        )
}
