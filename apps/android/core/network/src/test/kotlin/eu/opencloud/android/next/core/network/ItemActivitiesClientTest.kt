package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ItemActivitiesClientTest {
    @Test fun scopedQueryRendersNamesOnceAndOrdersByInstant() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(
                MockResponse().setBody(
                    """
                    {"value":[
                    {"id":"old","times":{"recordedTime":"2026-10-03T14:00:00+09:00"},
                    "template":{"message":"{user} changed {file} and {file}","variables":{
                    "user":{"displayName":"A {file}"},"file":{"name":"<Notes>"}}}},
                    {"id":"new","times":{"recordedTime":"2026-10-03T12:00:00Z"},
                    "template":{"message":"Created","variables":{}}}]}
                    """.trimIndent(),
                ),
            )
            val result =
                ItemActivitiesClient(OkHttpClient(), EndpointPolicy(true))
                    .list(server.url("/prefix/").toString(), "Bearer test", "storage!item")
            assertEquals(listOf("new", "old"), result.map { it.id })
            assertEquals("A {file} changed <Notes> and <Notes>", result.last().message)
            val request = server.takeRequest()
            assertEquals("/prefix/graph/v1beta1/extensions/org.libregraph/activities", request.requestUrl!!.encodedPath)
            assertEquals("itemid:storage!item AND limit:200 AND sort:desc", request.requestUrl!!.queryParameter("kql"))
            assertEquals("Bearer test", request.getHeader("Authorization"))
        }
    }

    @Test fun emptyMalformedAndForbiddenResponsesStayDistinct() {
        MockWebServer().use { server ->
            server.start()
            val client = ItemActivitiesClient(OkHttpClient(), EndpointPolicy(true))
            server.enqueue(MockResponse().setBody("""{"value":[]}"""))
            assertEquals(emptyList<ItemActivity>(), client.list(server.url("/").toString(), "test", "item"))
            server.enqueue(MockResponse().setBody("{}"))
            assertThrows(OpenCloudException::class.java) { client.list(server.url("/").toString(), "test", "item") }
            server.enqueue(MockResponse().setResponseCode(403))
            val error =
                assertThrows(TransferHttpException::class.java) {
                    client.list(server.url("/").toString(), "test", "item")
                }
            assertEquals(403, error.statusCode)
            assertThrows(IllegalArgumentException::class.java) {
                client.list(server.url("/").toString(), "test", "item OR *")
            }
            assertEquals(3, server.requestCount)
        }
    }

    @Test fun redirectsNeverForwardCredentials() {
        MockWebServer().use { server ->
            MockWebServer().use { other ->
                server.start()
                other.start()
                server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/")))
                assertThrows(TransferHttpException::class.java) {
                    ItemActivitiesClient(
                        OkHttpClient(),
                        EndpointPolicy(true),
                    ).list(server.url("/").toString(), "test", "item")
                }
                assertEquals(0, other.requestCount)
            }
        }
    }
}
