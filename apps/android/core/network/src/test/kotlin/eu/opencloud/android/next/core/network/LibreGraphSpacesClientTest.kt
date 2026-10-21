package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class LibreGraphSpacesClientTest {
    @Test fun `explicit vault discovery keeps encrypted spaces separate from ordinary spaces`() {
        val vault =
            drive("vault").replace(
                "\"driveType\":\"project\"",
                "\"driveType\":\"project\",\"@libre.graph.contentType\":\"application/vnd.opencloud.vault\"",
            )
        val body = """{"value":[${drive("visible")},$vault]}"""
        server.enqueue(MockResponse().setBody(body))
        server.enqueue(MockResponse().setBody(body))

        val ordinary = client.snapshot(server.url("/").toString(), "Bearer token")
        val explicit = client.snapshot(server.url("/").toString(), "Bearer token", includeVaultDetails = true)

        assertEquals(emptyList<RemoteSpace>(), ordinary.vaultSpaces)
        assertEquals(listOf("visible"), explicit.spaces.map { it.id })
        assertEquals(setOf("vault"), explicit.excludedVaultIds)
        assertEquals(listOf("vault"), explicit.vaultSpaces.map { it.id })
        assertEquals("vault-root", explicit.vaultSpaces.single().rootId)
    }

    @Test fun `snapshot retains explicit vault exclusions across pages without exposing drives`() {
        server.enqueue(
            MockResponse().setBody(
                """{"value":[${drive(
                    "visible",
                )},{"id":"vault-one","@libre.graph.contentType":"application/vnd.opencloud.vault"}],"@odata.nextLink":"?page=2"}""",
            ),
        )
        server.enqueue(
            MockResponse().setBody(
                """{"value":[{"id":"vault-two","@libre.graph.contentType":"application/vnd.opencloud.vault"}]}""",
            ),
        )
        val snapshot = client.snapshot(server.url("/").toString(), "Bearer token")
        assertEquals(listOf("visible"), snapshot.spaces.map { it.id })
        assertEquals(setOf("vault-one", "vault-two"), snapshot.excludedVaultIds)
    }

    @Test fun `vault ids participate in duplicate checks including conflicts with visible drives`() {
        listOf(
            """{"id":"same","@libre.graph.contentType":"application/vnd.opencloud.vault"}""",
            drive("same"),
        ).forEach { second ->
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{"id":"same","@libre.graph.contentType":"application/vnd.opencloud.vault"}],"@odata.nextLink":"?page=2"}""",
                ),
            )
            server.enqueue(MockResponse().setBody("""{"value":[$second]}"""))
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                client.snapshot(server.url("/").toString(), "Bearer token")
            }
        }
    }

    @Test fun `excluded drives require an identity and never survive failed pagination`() {
        listOf("", "\"id\":\"\",", "\"id\":\"   \",").forEach { id ->
            server.enqueue(
                MockResponse().setBody(
                    """{"value":[{$id"@libre.graph.contentType":"application/vnd.opencloud.vault"}]}""",
                ),
            )
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                client.snapshot(server.url("/").toString(), "Bearer token")
            }
        }
        server.enqueue(
            MockResponse().setBody(
                """{"value":[{"id":"vault","@libre.graph.contentType":"application/vnd.opencloud.vault"}],"@odata.nextLink":"?page=2"}""",
            ),
        )
        server.enqueue(MockResponse().setResponseCode(503))
        org.junit.Assert.assertThrows(TransferHttpException::class.java) {
            client.snapshot(server.url("/").toString(), "Bearer token")
        }
    }

    private lateinit var server: MockWebServer
    private lateinit var client: LibreGraphSpacesClient

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        client =
            LibreGraphSpacesClient(OkHttpClient(), initiatorId = "test-initiator", endpoints = EndpointPolicy(true))
    }

    @After
    fun tearDown() = server.shutdown()

    @Test
    fun `list spaces parses oCIS drive metadata`() {
        server.enqueue(
            MockResponse().setBody(
                """{"value":[{"id":"drive","driveAlias":"project-mars","name":"Mars","driveType":"project","description":"Mission files","webUrl":"https://cloud.example.test/f/drive","lastModifiedDateTime":"2026-09-09T12:00:00Z","owner":{"user":{"id":"alice","displayName":"Alice"}},"quota":{"total":100,"used":40,"remaining":60,"state":"normal"},"root":{"id":"root","webDavUrl":"${server.url(
                    "dav/spaces/drive",
                )}","eTag":"tag"}}]}""",
            ),
        )

        val result = client.listSpaces(server.url("/").toString(), "Bearer token").single()

        assertEquals("drive", result.id)
        assertEquals("project-mars", result.driveAlias)
        assertEquals("Alice", result.ownerName)
        assertEquals(100L, result.quotaTotalBytes)
        assertEquals(40L, result.quotaUsedBytes)
        assertEquals(60L, result.quotaRemainingBytes)
        val request = server.takeRequest()
        assertEquals("/graph/v1.0/me/drives", request.path)
        assertEquals("Bearer token", request.getHeader("Authorization"))
        assertEquals("test-initiator", request.getHeader("Initiator-ID"))
    }

    @Test
    fun `create project space posts only the requested name to the all drives endpoint`() {
        server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"new-drive"}"""))

        val createdId = client.createProjectSpace(server.url("/").toString(), "Bearer token", "  Mars  ")

        assertEquals("new-drive", createdId)
        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/graph/v1.0/drives", request.path)
        assertEquals("Bearer token", request.getHeader("Authorization"))
        assertEquals("test-initiator", request.getHeader("Initiator-ID"))
        assertEquals("application/json", request.getHeader("Content-Type")?.substringBefore(';'))
        assertEquals("""{"name":"Mars"}""", request.body.readUtf8())
    }

    @Test
    fun `create project space rejects unsuccessful responses and missing identities`() {
        server.enqueue(MockResponse().setResponseCode(403))
        assertThrows(TransferHttpException::class.java) {
            client.createProjectSpace(server.url("/").toString(), "Bearer token", "Mars")
        }
        server.enqueue(MockResponse().setResponseCode(201).setBody("{}"))
        assertThrows(OpenCloudException::class.java) {
            client.createProjectSpace(server.url("/").toString(), "Bearer token", "Mars")
        }
    }

    @Test
    fun `list spaces follows graph pagination`() {
        server.enqueue(
            MockResponse().setBody(
                """{"value":[${drive("one")}],"@odata.nextLink":"${server.url("graph/v1.0/me/drives?page=2")}"}""",
            ),
        )
        server.enqueue(MockResponse().setBody("""{"value":[${drive("two")}]}"""))

        assertEquals(listOf("one", "two"), client.listSpaces(server.url("/").toString(), "Bearer token").map { it.id })
        assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
        assertEquals("/graph/v1.0/me/drives?page=2", server.takeRequest().path)
    }

    @Test
    fun `cross origin page links never receive account credentials`() {
        MockWebServer().use { other ->
            other.start()
            server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"${other.url("/steal")}"}"""))
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                client.listSpaces(server.url("/").toString(), "Bearer secret")
            }
            assertEquals(0, other.requestCount)
        }
    }

    @Test
    fun `looping links failed pages and malformed envelopes do not return partial snapshots`() {
        server.enqueue(
            MockResponse().setBody("""{"value":[],"@odata.nextLink":"${server.url("graph/v1.0/me/drives")}"}"""),
        )
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.listSpaces(server.url("/").toString(), "Bearer secret")
        }
        assertEquals(1, server.requestCount)
        server.enqueue(MockResponse().setBody("""{"value":[${drive("one")}],"@odata.nextLink":"?page=2"}"""))
        server.enqueue(MockResponse().setResponseCode(503))
        org.junit.Assert.assertThrows(TransferHttpException::class.java) {
            client.listSpaces(server.url("/").toString(), "Bearer secret")
        }
        server.enqueue(MockResponse().setBody("{}"))
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.listSpaces(server.url("/").toString(), "Bearer secret")
        }
    }

    private fun drive(id: String): String =
        """{"id":"$id","name":"$id","driveType":"project","root":{"id":"$id-root","webDavUrl":"${server.url(
            "dav/spaces/$id",
        )}"}}"""
}
