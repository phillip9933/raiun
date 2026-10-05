package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class SpaceRepositoryTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var repository: SpaceRepository

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        store = FileBrowserStore(database)
        repository =
            SpaceRepository(
                store,
                LibreGraphSpacesClient(
                    OkHttpClient(),
                    initiatorId = "test",
                    endpoints =
                        eu.opencloud.android.next.core.network
                            .EndpointPolicy(true),
                ),
            )
    }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
    }

    @Test
    fun `synchronize replaces stale spaces and persists graph fields`() =
        runTest {
            store.replaceRemoteSpaces("account", listOf(staleSpace()))
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{"id":"project","driveAlias":"project-mars","name":"Mars","driveType":"project","owner":{"user":{"id":"alice","displayName":"Alice"}},"quota":{"total":100,"used":25,"remaining":75,"state":"normal"},"root":{"id":"root","webDavUrl":"${server.url(
                        "dav/spaces/project",
                    )}"}}]}""",
                ),
            )

            val synchronized = repository.synchronize("account", server.url("/").toString(), "Bearer token").single()

            assertEquals("project-mars", synchronized.driveAlias)
            assertEquals("Alice", synchronized.ownerName)
            assertEquals(25L, synchronized.quotaUsedBytes)
            assertEquals(synchronized, store.space("account", "project"))
            assertTrue(requireNotNull(store.space("account", "stale")).isDisabled)
        }

    @Test
    fun `superseded synchronization cannot overwrite a newer local space snapshot`() =
        runTest {
            store.replaceRemoteSpaces("account", listOf(staleSpace()))
            val releaseResponse = CountDownLatch(1)
            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        check(releaseResponse.await(5, TimeUnit.SECONDS))
                        return MockResponse().setBody(
                            """{"value":[{"id":"delayed","name":"Delayed","driveType":"project","root":{"id":"root","webDavUrl":"${server.url(
                                "dav/spaces/delayed",
                            )}"}}]}""",
                        )
                    }
                }

            val delayedSync =
                async(Dispatchers.IO) {
                    runCatching { repository.synchronize("account", server.url("/").toString(), "Bearer token") }
                }
            assertTrue(server.takeRequest(2, TimeUnit.SECONDS) != null)
            val newer = space("newer", "project")
            val newerToken = store.beginSnapshot("account")
            assertTrue(store.replaceRemoteSpaces("account", listOf(newer), newerToken))
            releaseResponse.countDown()

            assertTrue(delayedSync.await().exceptionOrNull() is SupersededDiscovery)

            assertEquals(newer, store.space("account", "newer"))
            assertEquals(null, store.space("account", "delayed"))
            assertTrue(requireNotNull(store.space("account", "stale")).isDisabled)
        }

    @Test
    fun `create project space posts remotely and persists it from the refreshed snapshot`() =
        runTest {
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"created-drive"}"""))
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{"id":"created-drive","name":"Mars","driveType":"project","root":{"id":"created-root","webDavUrl":"${server.url(
                        "dav/spaces/created-drive",
                    )}"}}]}""",
                ),
            )

            val result = repository.createProjectSpace("account", server.url("/").toString(), "Bearer token", "Mars")
            val created = (result as SpaceCreationResult.Created).space

            assertEquals("created-drive", created.driveId)
            assertEquals(created, store.space("account", "created-drive"))
            val post = server.takeRequest()
            assertEquals("POST", post.method)
            assertEquals("/graph/v1.0/drives", post.path)
            assertEquals("""{"name":"Mars"}""", post.body.readUtf8())
            assertEquals("GET", server.takeRequest().method)
        }

    @Test
    fun `acknowledged create retries discovery without posting twice`() =
        runTest {
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"created-drive"}"""))
            server.enqueue(MockResponse().setResponseCode(503))
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{"id":"created-drive","name":"Mars","driveType":"project","root":{"id":"root","webDavUrl":"${server.url(
                        "dav/spaces/created-drive",
                    )}"}}]}""",
                ),
            )

            val first = repository.createProjectSpace("account", server.url("/").toString(), "Bearer token", " Mars ")
            assertEquals(SpaceCreationResult.AwaitingDiscovery("created-drive"), first)
            val second = repository.createProjectSpace("account", server.url("/").toString(), "Bearer token", "Mars")
            assertEquals("created-drive", (second as SpaceCreationResult.Created).space.driveId)
            assertEquals("POST", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
        }

    @Test
    fun `pending create remains pending when complete snapshot omits its ID`() =
        runTest {
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"created-drive"}"""))
            server.enqueue(MockResponse().setBody("""{"value":[]}"""))
            server.enqueue(MockResponse().setBody("""{"value":[]}"""))

            assertEquals(
                SpaceCreationResult.AwaitingDiscovery("created-drive"),
                repository.createProjectSpace("account", server.url("/").toString(), "Bearer token", "Mars"),
            )
            assertEquals(
                SpaceCreationResult.AwaitingDiscovery("created-drive"),
                repository.createProjectSpace("account", server.url("/").toString(), "Bearer token", "Mars"),
            )
            assertEquals("POST", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
        }

    @Test
    fun `pending create journal survives repository and store recreation with isolated keys`() =
        runTest {
            val key = PendingSpaceCreationKey.create("account", server.url("/").toString(), "Mars")
            val preferences = RuntimeEnvironment.getApplication().getSharedPreferences("pending_space_creations", 0)
            preferences.edit().clear().commit()
            val firstStore = PendingSpaceCreations(RuntimeEnvironment.getApplication())
            firstStore.put(key, "drive-one")
            val recreated = PendingSpaceCreations(RuntimeEnvironment.getApplication())
            assertEquals("drive-one", recreated.get(key))
            recreated.put(key, "drive-two")
            val reopened = PendingSpaceCreations(RuntimeEnvironment.getApplication())
            assertEquals("drive-two", reopened.get(key))
            assertEquals(null, reopened.get(PendingSpaceCreationKey.create("other-account", key.serverUrl, "Mars")))
            assertEquals(
                null,
                reopened.get(PendingSpaceCreationKey.create("account", "https://other.example/", "Mars")),
            )
            assertEquals(null, reopened.get(PendingSpaceCreationKey.create("account", key.serverUrl, "mars")))
        }

    @Test
    fun `journal failure reports accepted creation as unsafe to retry`() =
        runTest {
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"accepted-drive"}"""))
            val noStorage =
                object : PendingSpaceCreationStore {
                    override fun get(key: PendingSpaceCreationKey): String? = null

                    override fun put(
                        key: PendingSpaceCreationKey,
                        driveId: String,
                    ) = error("disk unavailable")

                    override fun remove(key: PendingSpaceCreationKey) = Unit
                }
            val repositoryWithBrokenJournal = SpaceRepository(store, repositoryRemote(), noStorage)

            val result =
                repositoryWithBrokenJournal.createProjectSpace(
                    "account",
                    server.url("/").toString(),
                    "Bearer token",
                    "Mars",
                )

            assertEquals(SpaceCreationResult.AwaitingDiscovery("accepted-drive", retrySafe = false), result)
            assertEquals("POST", server.takeRequest().method)
            assertEquals(0, server.requestCount - 1)
        }

    @Test
    fun `journal cancellation propagates after the server acknowledges create`() =
        runTest {
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"accepted-drive"}"""))
            val cancelledJournal =
                object : PendingSpaceCreationStore {
                    override fun get(key: PendingSpaceCreationKey): String? = null

                    override fun put(
                        key: PendingSpaceCreationKey,
                        driveId: String,
                    ): Nothing = throw CancellationException("cancelled")

                    override fun remove(key: PendingSpaceCreationKey) = Unit
                }
            val repositoryWithCancelledJournal = SpaceRepository(store, repositoryRemote(), cancelledJournal)

            try {
                repositoryWithCancelledJournal.createProjectSpace(
                    "account",
                    server.url("/").toString(),
                    "Bearer token",
                    "Mars",
                )
                org.junit.Assert.fail("Cancellation must propagate")
            } catch (cancelled: CancellationException) {
                assertEquals("cancelled", cancelled.message)
            }
            assertEquals("POST", server.takeRequest().method)
        }

    @Test
    fun `project spaces exclude personal virtual and disabled drives`() =
        runTest {
            store.replaceRemoteSpaces(
                "account",
                listOf(
                    space("project", "project"),
                    space("personal", "personal"),
                    space("shares", "virtual", disabled = true),
                    space("disabled-project", "project", disabled = true),
                ),
            )

            val visible = repository.observeProjectSpaces("account").first()

            assertEquals(listOf("project"), visible.map { it.driveId })
        }

    @Test
    fun `page two failure preserves the previously committed space snapshot`() =
        runTest {
            store.replaceRemoteSpaces("account", listOf(staleSpace()))
            server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"?page=2"}"""))
            server.enqueue(MockResponse().setResponseCode(503))
            try {
                repository.synchronize("account", server.url("/").toString(), "Bearer secret")
                org.junit.Assert.fail("An incomplete snapshot must not be published")
            } catch (_: eu.opencloud.android.next.core.network.TransferHttpException) {
                assertEquals(listOf(staleSpace()), store.spaces("account"))
            }
        }

    private fun staleSpace() =
        SpaceEntity(
            accountId = "account",
            driveId = "stale",
            name = "Stale",
            type = "project",
            description = null,
            ownerName = null,
            rootId = "stale-root",
            rootWebDavUrl = "https://cloud.example.test/dav/spaces/stale",
            rootETag = null,
            quotaBytes = null,
        )

    private fun repositoryRemote() =
        LibreGraphSpacesClient(
            OkHttpClient(),
            initiatorId = "test",
            endpoints =
                eu.opencloud.android.next.core.network
                    .EndpointPolicy(true),
        )

    private fun space(
        id: String,
        type: String,
        disabled: Boolean = false,
    ) = SpaceEntity(
        accountId = "account",
        driveId = id,
        name = id,
        type = type,
        description = null,
        ownerName = null,
        rootId = "$id-root",
        rootWebDavUrl = "https://cloud.example.test/dav/spaces/$id",
        rootETag = null,
        quotaBytes = null,
        isDisabled = disabled,
    )
}
