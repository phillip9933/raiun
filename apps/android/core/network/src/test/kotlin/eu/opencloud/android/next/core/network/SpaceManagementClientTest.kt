package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.concurrent.CancellationException

class SpaceManagementClientTest {
    @Test
    fun `metadata lifecycle operations use documented Graph contracts`() {
        MockWebServer().use { server ->
            val client =
                LibreGraphSpacesClient(
                    OkHttpClient(),
                    initiatorId = "test-client",
                    endpoints = EndpointPolicy(allowLoopbackHttp = true),
                )
            server.enqueue(
                MockResponse().setResponseCode(200).setBody(
                    """{"id":"space${'$'}drive","name":"Mars","description":"Mission to Mars","driveType":"project","quota":{"total":500},"root":{"id":"root","webDavUrl":"${server.url(
                        "dav/root",
                    )}"}}""",
                ),
            )
            server.enqueue(MockResponse().setResponseCode(204))
            server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))
            server.enqueue(MockResponse().setResponseCode(204))

            val base = server.url("/").toString()
            client.updateProjectSpace(
                base,
                "Bearer token",
                "space\$drive",
                ProjectSpaceUpdate("Mars", "Mission to Mars", 500L),
            )
            client.disableProjectSpace(base, "Bearer token", "space\$drive")
            client.enableProjectSpace(base, "Bearer token", "space\$drive")
            client.permanentlyDeleteProjectSpace(base, "Bearer token", "space\$drive")

            val update = server.takeRequest()
            assertEquals("PATCH", update.method)
            assertEquals("/graph/v1.0/drives/space\$drive", update.path)
            assertEquals("Bearer token", update.getHeader("Authorization"))
            assertEquals("test-client", update.getHeader("Initiator-ID"))
            assertEquals(
                """{"name":"Mars","description":"Mission to Mars","quota":{"total":500}}""",
                update.body.readUtf8(),
            )

            val disable = server.takeRequest()
            assertEquals("DELETE", disable.method)
            assertEquals(null, disable.getHeader("Purge"))

            val enable = server.takeRequest()
            assertEquals("PATCH", enable.method)
            assertEquals("T", enable.getHeader("Restore"))
            assertEquals("{}", enable.body.readUtf8())

            val purge = server.takeRequest()
            assertEquals("DELETE", purge.method)
            assertEquals("T", purge.getHeader("Purge"))
        }
    }

    @Test
    fun `server authorization errors stay typed and cancellation is preserved`() {
        MockWebServer().use { server ->
            val client =
                LibreGraphSpacesClient(
                    OkHttpClient(),
                    endpoints = EndpointPolicy(allowLoopbackHttp = true),
                )
            server.enqueue(MockResponse().setResponseCode(403))
            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.updateProjectSpace(
                        server.url("/").toString(),
                        "Bearer token",
                        "space",
                        ProjectSpaceUpdate(name = "Mars"),
                    )
                }
            assertEquals(403, failure.statusCode)
            assertEquals(OpenCloudError.AccessDenied, failure.error)

            val cancelled = CancellationException("cancelled")
            val cancellingClient =
                LibreGraphSpacesClient(
                    OkHttpClient.Builder().addInterceptor { throw cancelled }.build(),
                    endpoints = EndpointPolicy(allowLoopbackHttp = true),
                )
            assertSame(
                cancelled,
                assertThrows(CancellationException::class.java) {
                    cancellingClient.disableProjectSpace(server.url("/").toString(), "Bearer token", "space")
                },
            )
        }
    }
}
