package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.WebFingerMetadata
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OidcScopeMetadataTest {
    private val server = MockWebServer().apply { start() }
    private val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
    private val serverUrl: String get() = server.url("/").toString().trimEnd('/')
    private val issuer: String get() = server.url("/").toString()

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `webfinger query includes android platform and preserves typed scopes`() {
        server.enqueue(
            MockResponse().setBody(
                """{"properties":{"http://opencloud.eu/ns/oidc/scopes":["openid","opencloud","token,with-comma"]}}""",
            ),
        )

        val metadata = api.webFinger(serverUrl)
        val request = server.takeRequest()

        assertEquals("android", request.requestUrl?.queryParameter("platform"))
        assertEquals(serverUrl, request.requestUrl?.queryParameter("resource"))
        assertEquals(listOf("openid", "opencloud", "token,with-comma"), metadata?.scopes)
    }

    @Test
    fun `missing and null webfinger scopes remain absent while an empty array is explicit`() {
        server.enqueue(MockResponse().setBody("""{"properties":{}}"""))
        assertNull(api.webFinger(serverUrl)?.scopes)

        server.enqueue(
            MockResponse().setBody(
                """{"properties":{"http://opencloud.eu/ns/oidc/scopes":null}}""",
            ),
        )
        assertNull(api.webFinger(serverUrl)?.scopes)

        server.enqueue(
            MockResponse().setBody(
                """{"properties":{"http://opencloud.eu/ns/oidc/scopes":[]}}""",
            ),
        )
        assertEquals(emptyList<String>(), api.webFinger(serverUrl)?.scopes)
    }

    @Test
    fun `webfinger normalizes OpenCloud scope text and mixed entries without splitting comma tokens`() {
        val cases =
            listOf(
                """["openid profile email offline_access"]""" to listOf("openid", "profile", "email", "offline_access"),
                """[" openid  profile ","opencloud token,with-comma"]""" to
                    listOf("openid", "profile", "opencloud", "token,with-comma"),
            )
        cases.forEach { (scopes, expected) ->
            server.enqueue(
                MockResponse().setBody(
                    """{"properties":{"http://opencloud.eu/ns/oidc/scopes":$scopes}}""",
                ),
            )
            assertEquals(expected, api.webFinger(serverUrl)?.scopes)
        }
    }

    @Test
    fun `webfinger rejects non-array and invalid scope tokens as controlled metadata errors`() {
        val malformed =
            listOf(
                "\"openid profile\"",
                "[\"openid\",7]",
                "[\"\"]",
                "[\" \"]",
                "[\"open\\tcloud\"]",
                "[\"open\\ncloud\"]",
                "[\"scöpe\"]",
                "[\"quo\\\"te\"]",
                "[\"back\\\\slash\"]",
            )
        malformed.forEach { scopes ->
            server.enqueue(
                MockResponse().setBody(
                    """{"properties":{"http://opencloud.eu/ns/oidc/scopes":$scopes}}""",
                ),
            )
            val failure =
                org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                    api.webFinger(serverUrl)
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
        }
    }

    @Test
    fun `valid webfinger scopes override unrelated provider scopes without parsing them`() {
        server.enqueue(
            MockResponse().setBody(
                """{"issuer":"$issuer","authorization_endpoint":"${issuer}authorize","token_endpoint":"${issuer}token","scopes_supported":false}""",
            ),
        )
        val configuration =
            api.oidcDiscovery(
                issuer,
                WebFingerMetadata(issuer = issuer, clientId = "mobile", scopes = listOf("openid", "opencloud")),
            )

        assertEquals(listOf("openid", "opencloud"), configuration.scopes)
    }

    @Test
    fun `provider scopes are typed and retained when webfinger metadata is absent or null`() {
        server.enqueue(discoveryBody("[\"openid\",\"opencloud\",\"token,with-comma\"]"))
        assertEquals(
            listOf("openid", "opencloud", "token,with-comma"),
            api.oidcDiscovery(issuer, null).scopes,
        )

        server.enqueue(discoveryBody("null"))
        assertEquals(listOf("openid", "profile"), api.oidcDiscovery(issuer, null).scopes)

        server.enqueue(discoveryBody("[]"))
        assertEquals(listOf("openid", "profile"), api.oidcDiscovery(issuer, null).scopes)
    }

    @Test
    fun `provider scopes reject malformed selected metadata as controlled errors`() {
        val malformed =
            listOf(
                "\"openid\"",
                "[\"openid\",true]",
                "[\"bad scope\"]",
                "[\"bad\\nscope\"]",
                "[\"scöpe\"]",
            )
        malformed.forEach { scopes ->
            server.enqueue(discoveryBody(scopes))
            val failure =
                org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                    api.oidcDiscovery(issuer, null)
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
        }
    }

    private fun discoveryBody(scopes: String) =
        MockResponse().setBody(
            """{"issuer":"$issuer","authorization_endpoint":"${issuer}authorize","token_endpoint":"${issuer}token","scopes_supported":$scopes}""",
        )
}
