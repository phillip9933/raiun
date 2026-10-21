package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SpaceManagementManagerTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        store = FileBrowserStore(database)
    }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
    }

    @Test
    fun `confirmed update refreshes only its target and retains other spaces`() =
        runTest {
            database.accountDao().upsert(
                AccountEntity("account", server.url("/").toString(), "alice", "Alice", "BASIC", false),
            )
            store.replaceRemoteSpaces("account", listOf(space("project"), space("personal", type = "personal")))
            server.enqueue(
                MockResponse().setResponseCode(200).setBody(
                    """{"id":"project","name":"Mars Updated","driveType":"project","description":"Subtitle","quota":{"total":500},"root":{"id":"project-root","webDavUrl":"${server.url(
                        "dav/project",
                    )}"}}""",
                ),
            )
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{"id":"project","name":"Mars Updated","driveType":"project","description":"Subtitle","quota":{"total":500,"used":120,"remaining":380,"state":"normal"},"root":{"id":"project-root","webDavUrl":"${server.url(
                        "dav/project",
                    )}"}}]}""",
                ),
            )
            val manager = manager()

            val updated = manager.update("account", "project", "Mars Updated", "Subtitle", 500)

            assertEquals("Mars Updated", updated.name)
            assertEquals("Subtitle", updated.description)
            assertEquals(500L, updated.quotaBytes)
            assertEquals("project", store.space("account", "project")?.driveId)
            assertEquals("personal", store.space("account", "personal")?.driveId)
            assertEquals("PATCH", server.takeRequest().method)
            val snapshot = server.takeRequest()
            assertEquals("GET", snapshot.method)
            assertEquals("/graph/v1.0/drives", snapshot.path)
        }

    @Test
    fun `denied update does not refresh or change local state`() =
        runTest {
            database.accountDao().upsert(
                AccountEntity("account", server.url("/").toString(), "alice", "Alice", "BASIC", false),
            )
            store.replaceRemoteSpaces("account", listOf(space("project")))
            server.enqueue(MockResponse().setResponseCode(403))

            val failure =
                try {
                    manager().update("account", "project", name = "Changed")
                    null
                } catch (caught: eu.opencloud.android.next.core.network.TransferHttpException) {
                    caught
                }

            assertEquals(403, failure?.statusCode)
            assertEquals("Project", store.space("account", "project")?.name)
            assertEquals(1, server.requestCount)
        }

    @Test
    fun `missing management target fails without changing cached spaces`() =
        runTest {
            store.replaceRemoteSpaces("account", listOf(space("project"), space("personal", type = "personal")))
            server.enqueue(MockResponse().setBody("""{"value":[]}"""))
            val repository =
                SpaceRepository(
                    store,
                    eu.opencloud.android.next.core.network.LibreGraphSpacesClient(
                        OkHttpClient(),
                        endpoints = EndpointPolicy(allowLoopbackHttp = true),
                    ),
                )

            val failure =
                try {
                    repository.synchronizeManagedSpace(
                        ManagedSpaceRefresh(
                            "account",
                            server.url("/").toString(),
                            "Bearer test",
                            "project",
                        ),
                    )
                    null
                } catch (caught: eu.opencloud.android.next.core.network.OpenCloudException) {
                    caught
                }

            assertEquals(
                eu.opencloud.android.next.core.network.OpenCloudError.PreconditionFailed,
                failure?.error,
            )
            assertEquals("Project", store.space("account", "project")?.name)
            assertEquals("Personal", store.space("account", "personal")?.name)
        }

    private fun manager() =
        SpaceManagementManager(
            RuntimeEnvironment.getApplication(),
            store,
            authorizationFor = { "Bearer test" },
            clientFor = { OkHttpClient() },
            endpointPolicy = EndpointPolicy(allowLoopbackHttp = true),
        )

    private fun space(
        id: String,
        type: String = "project",
    ) = SpaceEntity(
        accountId = "account",
        driveId = id,
        name = if (type == "personal") "Personal" else "Project",
        type = type,
        description = null,
        ownerName = null,
        rootId = "$id-root",
        rootWebDavUrl = server.url("dav/$id").toString(),
        rootETag = null,
        quotaBytes = null,
    )
}
