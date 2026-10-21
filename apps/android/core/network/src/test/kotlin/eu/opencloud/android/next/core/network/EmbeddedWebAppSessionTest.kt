package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.ServerAppProvider
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class EmbeddedWebAppSessionTest {
    private val server = MockWebServer()
    private val client = ServerWebAppClient(OkHttpClient(), EndpointPolicy(allowLoopbackHttp = true))
    private val provider = ServerAppProvider("/app/list", null, "/app/open")
    private val app = ServerWebApp("Office & Docs", "text/plain", null, false)
    private val registry = """{"mime-types":[{"mime_type":"text/plain","app_providers":[{"name":"Office & Docs"}]}]}"""

    @Before fun start() = server.start()

    @After fun stop() = server.shutdown()

    @Test fun `delegated POST session encodes fields without sending account auth to editor`() {
        val result =
            prepare(
                """{"app_url":"https://editor.example/wopi","method":"POST",
            "form_parameters":{"access_token":"secret+&=value","ui_defaults":"<script>"}}""",
            )
        assertEquals("POST", result.method)
        assertEquals("https://editor.example/wopi", result.url)
        assertEquals("access_token=secret%2B%26%3Dvalue&ui_defaults=%3Cscript%3E", result.postBody()!!.decodeToString())
        assertEquals("EmbeddedWebAppSession(redacted)", result.toString())
        server.takeRequest()
        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("drive!file", request.requestUrl!!.queryParameter("file_id"))
        assertEquals("Office & Docs", request.requestUrl!!.queryParameter("app_name"))
        assertEquals("view", request.requestUrl!!.queryParameter("view_mode"))
        assertEquals("Bearer account-secret", request.getHeader("Authorization"))
        assertEquals(0, request.bodySize)
        assertEquals(2, server.requestCount)
    }

    @Test fun `GET sessions keep query fragments transient and write mode is explicit`() {
        val result =
            prepare(
                """{"app_url":"https://editor.example/?token=secret#page","method":"GET","form_parameters":null}""",
                EmbeddedWebAppMode.WRITE,
            )
        assertNull(result.postBody())
        assertFalse(result.toString().contains("secret"))
        server.takeRequest()
        assertEquals("write", server.takeRequest().requestUrl!!.queryParameter("view_mode"))
    }

    @Test fun `unsafe editor URLs fail before any editor request`() {
        for (url in listOf(
            "http://editor.example/",
            "https://user:password@editor.example/",
            "file:///secret",
            "javascript:alert(1)",
            "/relative",
        )) {
            val error =
                assertThrows(OpenCloudException::class.java) {
                    prepare("""{"app_url":"$url","method":"GET"}""")
                }
            assertEquals(OpenCloudError.Trust, error.error)
        }
        assertEquals(10, server.requestCount)
    }

    @Test fun `malformed methods and oversized forms fail without exposing delegated secrets`() {
        for (fields in listOf(
            """"method":"PUT"""",
            """"method":"GET","form_parameters":{"token":"secret"}""",
            """"method":"POST","form_parameters":{"":"secret"}""",
            """"method":"POST","form_parameters":{"token":"${"s".repeat(65537)}"}""",
        )) {
            val error =
                assertThrows(OpenCloudException::class.java) {
                    prepare("""{"app_url":"https://editor.example/",$fields}""")
                }
            assertEquals(OpenCloudError.InvalidResponse, error.error)
            assertFalse(error.toString().contains("secret"))
        }
    }

    @Test fun `unadvertised and cross origin authenticated endpoints are rejected`() {
        val unsupported =
            assertThrows(OpenCloudException::class.java) {
                client.prepareEmbedded(
                    server.url("/").toString(),
                    provider.copy(openUrl = null),
                    "Bearer secret",
                    EmbeddedWebAppRequest("file", app),
                )
            }
        assertEquals(OpenCloudError.Unsupported, unsupported.error)
        val trust =
            assertThrows(OpenCloudException::class.java) {
                client.prepareEmbedded(
                    server.url("/").toString(),
                    provider.copy(openUrl = "https://evil.example/"),
                    "Bearer secret",
                    EmbeddedWebAppRequest("file", app),
                )
            }
        assertEquals(OpenCloudError.Trust, trust.error)
        assertEquals(0, server.requestCount)
    }

    private fun prepare(
        body: String,
        mode: EmbeddedWebAppMode = EmbeddedWebAppMode.VIEW,
    ): EmbeddedWebAppSession {
        server.enqueue(MockResponse().setBody(registry))
        server.enqueue(MockResponse().setBody(body))
        return client.prepareEmbedded(
            server.url("/").toString(),
            provider,
            "Bearer account-secret",
            EmbeddedWebAppRequest("drive!file", app, mode),
        )
    }
}
