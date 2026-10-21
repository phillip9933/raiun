package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class AccountProfileClientTest {
    private val server = MockWebServer()
    private val client = AccountProfileClient(OkHttpClient(), EndpointPolicy(allowLoopbackHttp = true))

    @Before fun start() = server.start()

    @After fun close() = server.shutdown()

    @Test fun profileUsesWebAccountFieldsAndGroupExpansion() {
        server.enqueue(
            MockResponse().setBody(
                """{"id":"opaque-id","onPremisesSamAccountName":"phil","displayName":"Phil Rogers","mail":"phil@example.test","memberOf":[{"displayName":"team"}]}""",
            ),
        )
        val profile = client.details(server.url("/cloud/").toString(), "Bearer token")
        assertEquals("phil", profile.username)
        assertEquals("Phil Rogers", profile.displayName)
        assertEquals(listOf("team"), profile.groups)
        val request = server.takeRequest()
        assertEquals("/cloud/graph/v1.0/me", request.requestUrl!!.encodedPath)
        assertEquals("memberOf", request.requestUrl!!.queryParameter("\$expand"))
        assertEquals("Bearer token", request.getHeader("Authorization"))
    }

    @Test fun photoUploadUsesRawPatchAndDeleteUsesOwnPhotoEndpoint() {
        server.enqueue(MockResponse().setResponseCode(204))
        client.uploadPhoto(server.url("/").toString(), "Bearer token", byteArrayOf(1, 2, 3), "image/jpeg")
        val upload = server.takeRequest()
        assertEquals("PATCH", upload.method)
        assertEquals("/graph/v1.0/me/photo/\$value", upload.path)
        assertEquals("image/jpeg", upload.getHeader("Content-Type"))
        assertArrayEquals(byteArrayOf(1, 2, 3), upload.body.readByteArray())
        server.enqueue(MockResponse().setResponseCode(204))
        client.removePhoto(server.url("/").toString(), "Bearer token")
        assertEquals("DELETE", server.takeRequest().method)
    }

    @Test fun missingPhotoIsAnInitialsFallbackButDeniedAccessIsAnError() {
        server.enqueue(MockResponse().setResponseCode(404))
        assertNull(client.photo(server.url("/").toString(), "Bearer token"))
        server.enqueue(MockResponse().setResponseCode(403).setBody("private server details"))
        val failure =
            assertThrows(TransferHttpException::class.java) { client.photo(server.url("/").toString(), "Bearer token") }
        assertEquals(OpenCloudError.AccessDenied, failure.error)
        assertFalse(failure.toString().contains("private server details"))
    }

    @Test fun redirectsCannotForwardAuthorizationToAnotherOrigin() {
        MockWebServer().use { other ->
            other.start()
            server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", other.url("/steal")))
            assertThrows(TransferHttpException::class.java) { client.photo(server.url("/").toString(), "Bearer token") }
            assertEquals(0, other.requestCount)
        }
    }

    @Test fun rejectsOversizeResponsesAndUnsupportedUploads() {
        server.enqueue(MockResponse().setBody("x".repeat(AccountProfileClient.MAX_PHOTO + 1)))
        assertThrows(OpenCloudException::class.java) { client.photo(server.url("/").toString(), "Bearer token") }
        assertThrows(IllegalArgumentException::class.java) {
            client.uploadPhoto(server.url("/").toString(), "Bearer token", byteArrayOf(1), "image/svg+xml")
        }
        assertEquals(1, server.requestCount)
    }
}
