package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SpaceMembersClientTest {
    @Test fun listsUserAndGroupMembershipsAndServerRoleChoices() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(
                MockResponse().setBody(
                    """
                    {"value":[
                      {"id":"user-permission","roles":["reader"],"grantedToV2":{"user":{"id":"u","displayName":"Alice"}}},
                      {"id":"group-permission","roles":["editor"],"grantedToV2":{"group":{"id":"g","displayName":"Team"}}},
                      {"id":"public","link":{"type":"view"},"roles":["reader"]}],
                     "@libre.graph.permissions.roles.allowedValues":[{"id":"reader","displayName":"Viewer"}]}
                    """.trimIndent(),
                ),
            )
            val result = client().list(server.url("/prefix/").toString(), "Bearer test", "space!root")
            assertEquals(listOf("Alice", "Team"), result.members.map { it.name })
            assertEquals(listOf(false, true), result.members.map { it.group })
            assertEquals(listOf(SpaceMemberRole("reader", "Viewer")), result.roles)
            val request = server.takeRequest()
            assertEquals("/prefix/graph/v1beta1/drives/space!root/root/permissions", request.path)
            assertEquals("Bearer test", request.getHeader("Authorization"))
        }
    }

    @Test fun mutationsTargetSelectedSpaceAndPermissionWithGraphPayloads() {
        MockWebServer().use { server ->
            server.start()
            val url = server.url("/").toString()
            server.enqueue(MockResponse().setResponseCode(204))
            client().add(url, "auth", "team", ShareRecipient(OcsShareType.GROUP, "g", "Team", null, true), "editor")
            val invite = server.takeRequest()
            assertEquals("POST", invite.method)
            assertEquals("/graph/v1beta1/drives/team/root/invite", invite.path)
            assertEquals(
                Json.parseToJsonElement(
                    """{"roles":["editor"],"recipients":[
                {"objectId":"g","@libre.graph.recipient.type":"group"}]}""",
                ),
                Json.parseToJsonElement(invite.body.readUtf8()),
            )
            server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))
            client().update(url, "auth", "team", "permission/a", "viewer")
            val update = server.takeRequest()
            assertEquals("PATCH", update.method)
            assertEquals("/graph/v1beta1/drives/team/root/permissions/permission%2Fa", update.path)
            assertEquals("[\"viewer\"]", Json.parseToJsonElement(update.body.readUtf8()).jsonObject["roles"].toString())
            server.enqueue(MockResponse().setResponseCode(204))
            client().remove(url, "auth", "team", "permission/a")
            val removal = server.takeRequest()
            assertEquals("DELETE", removal.method)
            assertEquals(update.path, removal.path)
        }
    }

    @Test fun rejectsIncompleteListingsForbiddenMutationsAndCredentialRedirects() {
        MockWebServer().use { server ->
            server.start()
            val url = server.url("/").toString()
            server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"/next"}"""))
            assertThrows(IllegalArgumentException::class.java) { client().list(url, "auth", "team") }
            server.enqueue(MockResponse().setResponseCode(403))
            assertThrows(TransferHttpException::class.java) { client().remove(url, "auth", "team", "permission") }
            MockWebServer().use { other ->
                other.start()
                server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/credentials")))
                assertThrows(TransferHttpException::class.java) { client().list(url, "auth", "team") }
                assertEquals(0, other.requestCount)
            }
        }
    }

    private fun client() = SpaceMembersClient(OkHttpClient(), EndpointPolicy(true))
}
