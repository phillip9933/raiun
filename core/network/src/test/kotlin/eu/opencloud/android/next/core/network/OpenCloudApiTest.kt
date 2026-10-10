package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream

class OpenCloudApiTest {
    private lateinit var server: MockWebServer
    private lateinit var api: OpenCloudApi

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `issuer mismatch is rejected before credentials can be sent`() {
        server.enqueue(
            MockResponse().setBody(
                """{"issuer":"https://unexpected.example","authorization_endpoint":"https://unexpected.example/auth","token_endpoint":"https://unexpected.example/token"}""",
            ),
        )
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            api.oidcDiscovery(server.url("/").toString(), null)
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `invalid grant produces controlled reauthentication without response text`() {
        server.enqueue(
            MockResponse().setResponseCode(400).setBody(
                """{"error":"invalid_grant","error_description":"private refresh token"}""",
            ),
        )
        val configuration =
            eu.opencloud.android.next.core.model.auth.OidcConfiguration(
                server.url("/").toString(),
                server.url("authorize").toString(),
                server.url("token").toString(),
                null,
                "registered",
                emptyList(),
            )
        val failure =
            org.junit.Assert.assertThrows(
                OpenCloudException::class.java,
            ) { api.refresh(configuration, "secret") }
        assertEquals(OpenCloudError.AuthenticationRequired, failure.error)
        assertFalse(failure.toString().contains("private"))
    }

    @Test
    fun `oversized oauth error is rejected before response parsing`() {
        server.enqueue(
            MockResponse().setResponseCode(400).setChunkedBody(
                "x".repeat(
                    ERROR_METADATA_LIMIT_BYTES.toInt() + 1,
                ),
                2048,
            ),
        )
        val configuration =
            eu.opencloud.android.next.core.model.auth.OidcConfiguration(
                server.url("/").toString(),
                server.url("authorize").toString(),
                server.url("token").toString(),
                null,
                "registered",
                emptyList(),
            )
        val failure =
            org.junit.Assert.assertThrows(
                OpenCloudException::class.java,
            ) { api.refresh(configuration, "secret") }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
    }

    @Test
    fun `discovery preserves an explicit canonical server scheme`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))

        val result = api.discover(server.url("/").toString().trimEnd('/'))

        assertEquals(server.url("/").toString().trimEnd('/'), result.canonicalServerUrl)
        assertEquals("/status.php", server.takeRequest().path)
    }

    @Test
    fun `metadata cap rejects chunked and compressed expansion beyond decoded byte limit`() {
        val oversized = metadataJsonOfSize(SMALL_METADATA_LIMIT_BYTES.toInt() + 1)
        server.enqueue(MockResponse().setChunkedBody(oversized, 4096))
        val chunkedFailure =
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                api.webFinger(server.url("/").toString().trimEnd('/'))
            }
        assertEquals(OpenCloudError.InvalidResponse, chunkedFailure.error)

        val compressed =
            ByteArrayOutputStream()
                .also { output ->
                    GZIPOutputStream(output).use { it.write(oversized.toByteArray()) }
                }.toByteArray()
        server.enqueue(
            MockResponse()
                .setHeader("Content-Encoding", "gzip")
                .setHeader("Content-Type", "application/json")
                .setBody(okio.Buffer().write(compressed)),
        )
        val gzipFailure =
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                api.webFinger(server.url("/").toString().trimEnd('/'))
            }
        assertEquals(OpenCloudError.InvalidResponse, gzipFailure.error)
    }

    @Test
    fun `metadata reader accepts exact byte limit and strips utf8 bom`() {
        server.enqueue(MockResponse().setBody(metadataJsonOfSize(SMALL_METADATA_LIMIT_BYTES.toInt())))
        assertEquals("https://issuer.example", api.webFinger(server.url("/").toString().trimEnd('/'))?.issuer)

        server.enqueue(
            MockResponse().setBody(
                "\uFEFF" +
                    """{"links":[{"rel":"http://opencloud.eu/ns/oidc/issuer","href":"https://issuer.example"}]}""",
            ),
        )
        assertEquals("https://issuer.example", api.webFinger(server.url("/").toString().trimEnd('/'))?.issuer)
    }

    @Test
    fun `metadata deadline preserves a shorter caller timeout`() {
        assertEquals(
            50,
            OkHttpClient
                .Builder()
                .callTimeout(50, TimeUnit.MILLISECONDS)
                .build()
                .withMetadataDeadline()
                .callTimeoutMillis,
        )
    }

    @Test
    fun `webfinger reads issuer and server supplied client metadata`() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"links":[{"rel":"http://opencloud.eu/ns/oidc/issuer","href":"https://issuer.example"}],"properties":{"http://opencloud.eu/ns/oidc/client_id":"mobile-client","http://opencloud.eu/ns/oidc/scopes":["openid","profile"]}}""",
            ),
        )

        val metadata = api.webFinger(server.url("/").toString().trimEnd('/'))

        assertEquals("https://issuer.example", metadata?.issuer)
        assertEquals("mobile-client", metadata?.clientId)
        assertEquals(listOf("openid", "profile"), metadata?.scopes)
    }

    @Test fun `standard webfinger issuer on a separate origin is used for discovery`() {
        MockWebServer().use { identity ->
            val issuer = identity.url("/").toString()
            server.enqueue(MockResponse().setBody("{}"))
            server.enqueue(
                MockResponse().setBody(
                    """{"links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"$issuer"}]}""",
                ),
            )
            identity.enqueue(
                MockResponse().setBody(
                    """{"issuer":"$issuer","authorization_endpoint":"${issuer}authorize","token_endpoint":"${issuer}token"}""",
                ),
            )
            val discovered = api.discover(server.url("/").toString())
            val metadata = requireNotNull(api.webFinger(discovered.canonicalServerUrl))
            val configuration = api.oidcDiscovery(requireNotNull(metadata.issuer), metadata)
            assertEquals(issuer, configuration.issuer)
            assertEquals("${issuer}authorize", configuration.authorizationEndpoint)
            server.takeRequest()
            assertEquals(
                "http://openid.net/specs/connect/1.0/issuer",
                server.takeRequest().requestUrl?.queryParameter("rel"),
            )
            assertEquals("/.well-known/openid-configuration", identity.takeRequest().path)
        }
    }

    @Test
    fun `basic profile and capabilities send required authorization and OCS headers`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(userResponse()))
        server.enqueue(MockResponse().setResponseCode(200).setBody(capabilitiesResponse()))
        val baseUrl = server.url("/").toString().trimEnd('/')

        val profile = api.basicProfile(baseUrl, "alice", "secret")
        val capabilities = api.capabilities(baseUrl, "Basic YWxpY2U6c2VjcmV0")

        assertEquals("alice", profile.id)
        assertTrue(capabilities.sharingEnabled)
        assertEquals("$baseUrl/remote.php/dav/spaces/", capabilities.remoteSearchUrl)
        assertTrue(capabilities.trashSupported)
        assertTrue(capabilities.publicLinkPasswordSupported)
        assertTrue(capabilities.publicLinkPasswordEnforced)
        assertTrue(capabilities.publicLinkExpirationSupported)
        assertEquals(30, capabilities.publicLinkExpirationDays)
        assertEquals("Basic YWxpY2U6c2VjcmV0", server.takeRequest().getHeader("Authorization"))
        val capabilitiesRequest = server.takeRequest()
        assertEquals("true", capabilitiesRequest.getHeader("OCS-APIREQUEST"))
        assertEquals("/ocs/v1.php/cloud/capabilities?format=json", capabilitiesRequest.path)
    }

    @Test
    fun `trash capability accepts boolean and newer version values`() {
        val baseUrl = server.url("/").toString().trimEnd('/')
        server.enqueue(MockResponse().setResponseCode(200).setBody(capabilitiesResponse("true")))
        server.enqueue(MockResponse().setResponseCode(200).setBody(capabilitiesResponse("\"2.0\"")))
        server.enqueue(
            MockResponse()
                .setResponseCode(
                    200,
                ).setBody(capabilitiesResponse("{\"enabled\":false,\"version\":\"1.0\"}")),
        )

        assertTrue(api.capabilities(baseUrl, "Bearer token").trashSupported)
        assertTrue(api.capabilities(baseUrl, "Bearer token").trashSupported)
        assertFalse(api.capabilities(baseUrl, "Bearer token").trashSupported)
    }

    @Test
    fun `oCIS nested sharing api capability enables sharing`() {
        val baseUrl = server.url("/").toString().trimEnd('/')
        server.enqueue(MockResponse().setResponseCode(200).setBody(ocisCapabilitiesResponse()))

        val capabilities = api.capabilities(baseUrl, "Bearer token")

        assertTrue(capabilities.sharingEnabled)
        assertTrue(capabilities.publicSharingEnabled)
        assertTrue(capabilities.publicLinkPasswordSupported)
        assertTrue(capabilities.publicLinkExpirationSupported)
        assertEquals(14, capabilities.publicLinkExpirationDays)
    }

    @Test
    fun `sharing is disabled when capability is disabled or malformed`() {
        val baseUrl = server.url("/").toString().trimEnd('/')
        server.enqueue(MockResponse().setResponseCode(200).setBody(disabledSharingCapabilitiesResponse()))
        server.enqueue(MockResponse().setResponseCode(200).setBody("not-json"))

        assertFalse(api.capabilities(baseUrl, "Bearer token").sharingEnabled)
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            api.capabilities(baseUrl, "Bearer token")
        }
    }

    @Test
    fun `token exchange and refresh use their expected grant types`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(tokenResponse("access-1", "refresh-1")))
        server.enqueue(MockResponse().setResponseCode(200).setBody(tokenResponse("access-2", "refresh-2")))
        val configuration =
            eu.opencloud.android.next.core.model.auth.OidcConfiguration(
                issuer = server.url("/").toString(),
                authorizationEndpoint = server.url("authorize").toString(),
                tokenEndpoint = server.url("token").toString(),
                registrationEndpoint = null,
                clientId = "server-advertised-client",
                scopes = listOf("openid"),
            )

        val exchanged = api.exchangeCode(configuration, "code", NEXT_OIDC_REDIRECT_URI, "verifier")
        val refreshed = api.refresh(configuration, "refresh-1")

        assertEquals("access-1", exchanged.accessToken)
        assertEquals("access-2", refreshed.accessToken)
        val authorizationCodeRequest = server.takeRequest().body.readUtf8()
        val refreshRequest = server.takeRequest().body.readUtf8()
        assertTrue(authorizationCodeRequest.contains("grant_type=authorization_code"))
        assertTrue(authorizationCodeRequest.contains("client_id=server-advertised-client"))
        assertTrue(refreshRequest.contains("grant_type=refresh_token"))
        assertTrue(refreshRequest.contains("client_id=server-advertised-client"))
    }

    private fun userResponse() =
        """{"ocs":{"data":{"id":"alice","display-name":"Alice","email":"alice@example.test"}}}"""

    private fun metadataJsonOfSize(size: Int): String {
        val prefix =
            """{"links":[{"rel":"http://opencloud.eu/ns/oidc/issuer","href":"https://issuer.example"}],"padding":""""
        val suffix = "\"}"
        return prefix + "x".repeat(size - prefix.length - suffix.length) + suffix
    }

    private fun capabilitiesResponse(trashbin: String = "\"1.0\"") =
        """{"ocs":{"data":{"version":{"string":"7.4.0"},"capabilities":{"dav":{"reports":["search-files"],"trashbin":$trashbin},"files":{"tus_support":{"version":"1.0.0","resumable":"1.0.0"}},"files_sharing":{"api_enabled":true,"public":{"enabled":true,"password":{"enforced":true},"expire_date":{"enabled":true,"days":30,"enforced":false}}},"spaces":{"enabled":true}}}}}"""

    private fun ocisCapabilitiesResponse() =
        """{"ocs":{"data":{"version":{"string":"7.2.0"},"capabilities":{"files_sharing":{"api":{"api_enabled":1},"public":{"api_enabled":"true","password":{"enforced":false},"expire_date":{"enabled":true,"days":14}}}}}}}"""

    private fun disabledSharingCapabilitiesResponse() =
        """{"ocs":{"data":{"version":{"string":"7.2.0"},"capabilities":{"files_sharing":{"api_enabled":false}}}}}"""

    private fun tokenResponse(
        accessToken: String,
        refreshToken: String,
    ) = """{"access_token":"$accessToken","refresh_token":"$refreshToken","expires_in":3600,"token_type":"Bearer"}"""
}
