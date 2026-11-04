package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class OAuthFailureClassificationTest {
    @Test fun `only explicit grant or client errors request destructive reauthentication`() {
        MockWebServer().use { server ->
            server.start()
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            val configuration =
                OidcConfiguration(
                    server.url("/").toString(),
                    server.url("authorize").toString(),
                    server.url("token").toString(),
                    null,
                    "client",
                    listOf("openid"),
                )
            val cases =
                listOf(
                    Triple(401, "", OpenCloudError.HttpFailure(401)),
                    Triple(401, "<html>private-proxy-message</html>", OpenCloudError.HttpFailure(401)),
                    Triple(
                        401,
                        """{"error":"unknown","error_description":"private-token"}""",
                        OpenCloudError.HttpFailure(401),
                    ),
                    Triple(400, """{"error":"invalid_grant"}""", OpenCloudError.AuthenticationRequired),
                    Triple(401, """{"error":"invalid_grant"}""", OpenCloudError.AuthenticationRequired),
                    Triple(400, """{"error":"invalid_client"}""", OpenCloudError.ClientRegistrationRequired),
                    Triple(401, """{"error":"invalid_client"}""", OpenCloudError.ClientRegistrationRequired),
                    Triple(503, "private-temporary-error", OpenCloudError.ServerFailure(503, null)),
                )
            cases.forEach { (status, body, expected) ->
                server.enqueue(MockResponse().setResponseCode(status).setBody(body))
                val failure =
                    assertThrows(OpenCloudException::class.java) { api.refresh(configuration, "private-refresh") }
                assertEquals(expected, failure.error)
                assertFalse(failure.toString().contains("private"))
            }
        }
    }
}
