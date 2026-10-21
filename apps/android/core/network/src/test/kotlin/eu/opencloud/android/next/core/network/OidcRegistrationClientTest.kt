package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class OidcRegistrationClientTest {
    private lateinit var server: MockWebServer
    private lateinit var registration: OidcRegistrationClient

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        registration = OidcRegistrationClient(OkHttpClient(), EndpointPolicy(allowLoopbackHttp = true))
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `registration sends exact native public client metadata without credentials`() {
        server.enqueue(MockResponse().setResponseCode(201).setBody(response()))
        val result = registration.register("https://cloud.example", configuration())
        assertEquals("registered-client", result.clientId)
        assertFalse(result.toString().contains("management-secret"))
        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertNull(request.getHeader("Authorization"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"token_endpoint_auth_method\":\"none\""))
        assertTrue(body.contains("\"client_name\":\"Raiun\""))
        assertTrue(body.contains(NEXT_OIDC_REDIRECT_URI))
        assertTrue(body.contains("refresh_token"))
    }

    @Test fun `unsupported auth methods and changed redirects are rejected`() {
        listOf(
            response().replace("\"none\"", "\"client_secret_basic\""),
            response().replace(NEXT_OIDC_REDIRECT_URI, "evil://callback"),
        ).forEach { body ->
            server.enqueue(MockResponse().setResponseCode(201).setBody(body))
            assertThrows(
                OpenCloudException::class.java,
            ) { registration.register("https://cloud.example", configuration()) }
        }
    }

    @Test fun `registration never follows redirects or echoes protected endpoint errors`() {
        server.enqueue(MockResponse().setResponseCode(307).setHeader("Location", server.url("unexpected")))
        assertThrows(
            TransferHttpException::class.java,
        ) { registration.register("https://cloud.example", configuration()) }
        assertEquals(1, server.requestCount)
        server.enqueue(MockResponse().setResponseCode(401).setBody("management-secret"))
        val failure =
            assertThrows(TransferHttpException::class.java) {
                registration.register("https://cloud.example", configuration())
            }
        assertFalse(failure.toString().contains("management-secret"))
    }

    @Test fun `production endpoint policy rejects insecure and credential-bearing endpoints`() {
        val policy = EndpointPolicy()
        listOf("http://cloud.example", "https://user:secret@cloud.example", "https://cloud.example/#fragment")
            .forEach { assertThrows(OpenCloudException::class.java) { policy.endpoint(it) } }
        assertEquals("https://data.example/oidc/token", policy.endpoint("https://data.example/oidc/token").toString())
    }

    private fun configuration() =
        OidcConfiguration(
            "https://issuer.example",
            "https://issuer.example/authorize",
            "https://issuer.example/token",
            server.url("register").toString(),
            null,
            listOf("openid"),
        )

    private fun response() =
        """{"client_id":"registered-client","redirect_uris":["$NEXT_OIDC_REDIRECT_URI"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","registration_access_token":"management-secret"}"""
}
