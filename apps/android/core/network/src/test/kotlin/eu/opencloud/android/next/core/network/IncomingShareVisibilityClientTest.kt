package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class IncomingShareVisibilityClientTest {
    @Test fun visibilityTargetsRecipientEntryAndNeverOwnerFolder() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(MockResponse().setResponseCode(204))
            server.enqueue(MockResponse().setResponseCode(204))
            val item =
                IncomingSharedItem(
                    "recipient-entry",
                    SharedRemoteItem("owner-folder"),
                    parentReference = SharedParentReference("recipient-drive"),
                )
            val client = IncomingShareVisibilityClient(OkHttpClient(), EndpointPolicy(true))
            client.setHidden(server.url("/prefix/").toString(), "Bearer test", item, true)
            val hide = server.takeRequest()
            assertEquals("PATCH", hide.method)
            assertEquals("/prefix/graph/v1beta1/drives/recipient-drive/items/recipient-entry", hide.path)
            assertEquals("{\"@UI.Hidden\":true}", hide.body.readUtf8())
            client.setHidden(server.url("/prefix/").toString(), "Bearer test", item, false)
            assertEquals("{\"@UI.Hidden\":false}", server.takeRequest().body.readUtf8())
        }
    }

    @Test fun missingRecipientDriveAndServerFailuresAreNotSuccess() {
        MockWebServer().use { server ->
            server.start()
            val client = IncomingShareVisibilityClient(OkHttpClient(), EndpointPolicy(true))
            val item = IncomingSharedItem("share", SharedRemoteItem("owner"))
            assertThrows(IllegalArgumentException::class.java) {
                client.setHidden(server.url("/").toString(), "Bearer test", item, true)
            }
            assertEquals(0, server.requestCount)
            server.enqueue(MockResponse().setResponseCode(403))
            assertThrows(TransferHttpException::class.java) {
                client.setHidden(
                    server.url("/").toString(),
                    "Bearer test",
                    item.copy(parentReference = SharedParentReference("recipient")),
                    true,
                )
            }
        }
    }

    @Test fun inventoryRetainsDisplayMetadataWithoutTreatingItAsAccess() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(
                MockResponse().setBody(
                    """
                    {"value":[{"id":"share","name":"Shared","folder":{},"@UI.Hidden":true,
                    "parentReference":{"driveId":"recipient"},"size":123,"lastModifiedDateTime":"2026-10-03T12:00:00Z",
                    "remoteItem":{"id":"owner-folder","createdBy":{"user":{"id":"owner","displayName":"Owner"}},
                    "permissions":[{"createdDateTime":"2026-10-02T12:00:00Z",
                    "invitation":{"invitedBy":{"user":{"id":"sender","displayName":"Sender"}}}}]}}]}
                    """.trimIndent(),
                ),
            )
            val item =
                IncomingSharesClient(
                    OkHttpClient(),
                    EndpointPolicy(true),
                ).list(server.url("/").toString(), "test").single()
            assertEquals(true, item.hidden)
            assertEquals("recipient", item.parentReference?.driveId)
            assertEquals(
                "Owner",
                item.remoteItem.createdBy
                    ?.user
                    ?.displayName,
            )
            assertEquals(
                "Sender",
                item.remoteItem.permissions
                    ?.single()
                    ?.invitation
                    ?.invitedBy
                    ?.user
                    ?.displayName,
            )
            assertEquals(null, item.effectiveActions)
        }
    }
}
