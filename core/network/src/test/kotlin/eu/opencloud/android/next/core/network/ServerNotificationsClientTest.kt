package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ServerNotificationsClientTest {
    @Test fun openCloudNilInboxIsEmptyButMalformedEnvelopesStillFail() {
        MockWebServer().use { server ->
            server.start()
            val client = ServerNotificationsClient(OkHttpClient(), EndpointPolicy(true))
            server.enqueue(MockResponse().setBody("""{"ocs":{"meta":{"statuscode":200},"data":null}}"""))
            assertEquals(emptyList<ServerNotification>(), client.list(server.url("/").toString(), "test"))
            server.enqueue(MockResponse().setBody("""{"ocs":{"meta":{"statuscode":200}}}"""))
            assertThrows(OpenCloudException::class.java) { client.list(server.url("/").toString(), "test") }
            server.enqueue(MockResponse().setBody("""{"ocs":{"meta":{"statuscode":403},"data":null}}"""))
            assertThrows(OpenCloudException::class.java) { client.list(server.url("/").toString(), "test") }
        }
    }

    @Test fun parsesOcsInboxAndSubstitutesRichNamesAsPlainText() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(
                MockResponse().setBody(
                    """
                    {"ocs":{"meta":{"statuscode":200},"data":[
                    {"notification_id":42,"subject":"New share","message":"Fallback",
                    "messageRich":"{user} shared {resource}",
                    "messageRichParameters":{"user":{"displayname":"Someone"},"resource":{"name":"<Notes>"}},
                    "datetime":"2026-10-03T12:00:00Z","object_type":"share"}]}}
                    """.trimIndent(),
                ),
            )
            val result =
                ServerNotificationsClient(OkHttpClient(), EndpointPolicy(true))
                    .list(server.url("/prefix/").toString(), "Bearer test")
                    .single()
            assertEquals("42", result.id)
            assertEquals("Someone shared <Notes>", result.message)
            assertEquals(true, result.isShare)
            val request = server.takeRequest()
            assertEquals("/prefix/ocs/v2.php/apps/notifications/api/v1/notifications", request.path)
            assertEquals("true", request.getHeader("OCS-APIRequest"))
        }
    }

    @Test fun markReadUsesExplicitIdsAndDoesNotAcceptServerErrors() {
        MockWebServer().use { server ->
            server.start()
            val client = ServerNotificationsClient(OkHttpClient(), EndpointPolicy(true))
            server.enqueue(MockResponse().setResponseCode(204))
            client.markRead(server.url("/").toString(), "test", listOf("42", "43"))
            val request = server.takeRequest()
            assertEquals("DELETE", request.method)
            assertEquals("{\"ids\":[\"42\",\"43\"]}", request.body.readUtf8())
            server.enqueue(MockResponse().setResponseCode(500))
            assertThrows(
                TransferHttpException::class.java,
            ) { client.markRead(server.url("/").toString(), "test", listOf("42")) }
            server.enqueue(MockResponse().setBody("""{"ocs":{"meta":{"statuscode":403},"data":[]}}"""))
            assertThrows(OpenCloudException::class.java) { client.list(server.url("/").toString(), "test") }
        }
    }

    @Test fun emptyResponseIsEmptyAndForeignRedirectsDoNotReceiveCredentials() {
        MockWebServer().use { server ->
            server.start()
            val client = ServerNotificationsClient(OkHttpClient(), EndpointPolicy(true))
            server.enqueue(MockResponse().setResponseCode(204))
            assertEquals(emptyList<ServerNotification>(), client.list(server.url("/").toString(), "test"))
            MockWebServer().use { foreign ->
                foreign.start()
                server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", foreign.url("/secret")))
                assertThrows(TransferHttpException::class.java) { client.list(server.url("/").toString(), "test") }
                assertEquals(0, foreign.requestCount)
            }
        }
    }
}
