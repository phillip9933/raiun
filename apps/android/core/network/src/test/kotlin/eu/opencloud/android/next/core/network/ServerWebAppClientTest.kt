package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.ServerAppProvider
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CancellationException

class ServerWebAppClientTest {
    private val server = MockWebServer()
    private val client = ServerWebAppClient(OkHttpClient(), EndpointPolicy(allowLoopbackHttp = true))
    private val provider = ServerAppProvider("/app/list", "/app/open-web")
    private val choice = ServerWebApp("Office & Docs", "text/plain", "txt", true)
    private val registry = """{"mime-types":[{"mime_type":"text/plain","ext":"txt",
        "default_application":"Office & Docs","app_providers":[{"name":"Office & Docs","icon":"https://other/icon"}]}]}"""

    @Before fun start() = server.start()

    @After fun stop() = server.shutdown()

    @Test fun `registry maps types without fetching icons and browser handoff encodes selection`() {
        server.enqueue(MockResponse().setBody(registry))
        assertEquals(listOf(choice), client.list(server.url("/cloud").toString(), provider, "Bearer token"))
        assertEquals("/app/list", server.takeRequest().path)
        server.enqueue(MockResponse().setBody(registry))
        server.enqueue(MockResponse().setBody("""{"uri":"/web/#/external/file"}"""))
        val url = client.openInWeb(server.url("/").toString(), provider, "Bearer token", "drive!file", choice)
        assertEquals(server.url("/web/#/external/file").toString(), url)
        server.takeRequest()
        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/app/open-web", request.path)
        assertEquals("file_id=drive%21file&app_name=Office%20%26%20Docs", request.body.readUtf8())
        assertEquals("Bearer token", request.getHeader("Authorization"))
        assertEquals(3, server.requestCount)
    }

    @Test fun `credential endpoints cannot change origin or use userinfo fragments or cleartext`() {
        for (url in listOf(
            "https://evil.test/list",
            "https://user:pass@cloud.test/list",
            "http://cloud.test/list",
            "/app/list#secret",
        )) {
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.list("https://cloud.test/", provider.copy(appsUrl = url), "Bearer token")
                }
            assertEquals(OpenCloudError.Trust, failure.error)
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun `relative advertised endpoints retain the server base path`() {
        server.enqueue(MockResponse().setBody(registry))
        client.list(server.url("/cloud").toString(), provider.copy(appsUrl = "app/list"), "Bearer token")
        assertEquals("/cloud/app/list", server.takeRequest().path)
    }

    @Test fun `redirect errors and malformed responses do not leak response content`() {
        for (code in listOf(302, 401, 403, 429)) {
            server.enqueue(
                MockResponse()
                    .setResponseCode(code)
                    .addHeader("Location", "https://evil.test/")
                    .addHeader("Retry-After", "25")
                    .setBody("private-response"),
            )
            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.list(server.url("/").toString(), provider, "Bearer token")
                }
            assertFalse(failure.toString().contains("private-response"))
            if (code == 429) assertEquals(OpenCloudError.RateLimited(25), failure.error)
        }
        for (body in listOf(
            "private-response",
            "{}",
            registry.replace("text/plain", "invalid"),
            """{"mime-types":[{"mime_type":"text/plain","app_providers":[{"name":""}]}]}""",
        )) {
            server.enqueue(MockResponse().setBody(body))
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.list(server.url("/").toString(), provider, "Bearer token")
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertFalse(failure.toString().contains(body))
        }
        assertEquals(8, server.requestCount)
    }

    @Test fun `stale applications and unsafe launch destinations are rejected`() {
        server.enqueue(MockResponse().setBody("""{"mime-types":[]}"""))
        assertThrows(OpenCloudException::class.java) {
            client.openInWeb(server.url("/").toString(), provider, "Bearer token", "file", choice)
        }
        assertEquals(1, server.requestCount)
        for (uri in listOf("https://evil.test/token", "intent://launch", "javascript:alert(1)")) {
            server.enqueue(MockResponse().setBody(registry))
            server.enqueue(MockResponse().setBody("""{"uri":"$uri"}"""))
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.openInWeb(server.url("/").toString(), provider, "Bearer token", "file", choice)
                }
            assertEquals(OpenCloudError.Trust, failure.error)
        }
    }

    @Test fun `bounded responses reject oversized metadata and cancellation remains cancellation`() {
        server.enqueue(MockResponse().setBody("x".repeat(2 * 1024 * 1024 + 1)))
        assertThrows(OpenCloudException::class.java) {
            client.list(server.url("/").toString(), provider, "Bearer token")
        }
        val cancelled =
            ServerWebAppClient(
                OkHttpClient.Builder().addInterceptor { throw CancellationException() }.build(),
                EndpointPolicy(allowLoopbackHttp = true),
            )
        assertThrows(CancellationException::class.java) {
            cancelled.list(server.url("/").toString(), provider, "Bearer token")
        }
    }
}
