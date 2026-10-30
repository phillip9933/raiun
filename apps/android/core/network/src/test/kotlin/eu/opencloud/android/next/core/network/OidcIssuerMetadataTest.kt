package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcIssuerMetadataTest {
    @Test fun `issuer retains validated identifier spelling rather than normalizing URL identity`() {
        val policy = EndpointPolicy()
        listOf(
            "https://ID.example:443",
            "https://id.example",
            "https://id.example/",
            "https://id.example/one/../tenant",
        ).forEach { issuer -> assertEquals(issuer, policy.issuer(issuer)) }
        assertNotEquals(policy.issuer("https://id.example"), policy.issuer("https://ID.example"))
        assertNotEquals(policy.issuer("https://id.example"), policy.issuer("https://id.example:443"))
        assertNotEquals(policy.issuer("https://id.example"), policy.issuer("https://id.example/"))
        listOf(
            "http://id.example",
            "https://user@id.example",
            "https://id.example?query",
            "https://id.example#fragment",
            " https://id.example",
            "https://id.example\n",
        ).forEach { issuer -> assertThrows(OpenCloudException::class.java) { policy.issuer(issuer) } }
    }

    @Test fun `discovery rejects normalized-equivalent issuer metadata and retains exact match`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            val issuer = server.url("/tenant").toString()
            listOf(issuer.replace("localhost", "LOCALHOST"), "$issuer/", issuer.replace("/tenant", "/one/../tenant"))
                .forEach { returned ->
                    server.enqueue(discovery(returned))
                    val failure = assertThrows(OpenCloudException::class.java) { api.oidcDiscovery(issuer, null) }
                    assertEquals(OpenCloudError.Trust, failure.error)
                }
            server.enqueue(discovery(issuer))
            assertEquals(issuer, api.oidcDiscovery(issuer, null).issuer)
        }
    }

    @Test fun `selected WebFinger issuer and client identifiers require nonempty JSON strings`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            listOf(
                """{"links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":7}]}""",
                """{"links":[{"rel":"http://openid.net/specs/connect/1.0/issuer"}]}""",
                """{"properties":{"http://opencloud.eu/ns/oidc/client_id":true}}""",
                """{"properties":{"http://opencloud.eu/ns/oidc/client_id":""}}""",
            ).forEach { body ->
                server.enqueue(MockResponse().setBody(body))
                val failure = assertThrows(OpenCloudException::class.java) { api.webFinger(server.url("/").toString()) }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            }
        }
    }

    @Test fun `discovery requires typed issuer and endpoint strings`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            val issuer = server.url("/tenant").toString()
            listOf(
                """{"issuer":null}""",
                """{"issuer":7}""",
                """{"issuer":"$issuer","authorization_endpoint":true,"token_endpoint":"https://id.example/token"}""",
            ).forEach { body ->
                server.enqueue(MockResponse().setBody(body))
                val failure = assertThrows(OpenCloudException::class.java) { api.oidcDiscovery(issuer, null) }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            }
        }
    }

    @Test fun `response issuer support defaults only when absent and requires a JSON boolean`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            val issuer = server.url("/tenant").toString()
            listOf(null to false, "false" to false, "true" to true).forEach { (flag, expected) ->
                server.enqueue(discovery(issuer, flag))
                assertEquals(expected, api.oidcDiscovery(issuer, null).authorizationResponseIssParameterSupported)
            }
            listOf("null", "\"true\"", "0", "[]", "{}").forEach { flag ->
                server.enqueue(discovery(issuer, flag))
                val failure = assertThrows(OpenCloudException::class.java) { api.oidcDiscovery(issuer, null) }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            }
        }
    }

    private fun discovery(
        issuer: String,
        issuerFlag: String? = null,
    ) = MockResponse().setBody(
        """{"issuer":"$issuer","authorization_endpoint":"https://id.example/authorize","token_endpoint":"https://id.example/token"${issuerFlag?.let {
            ",\"authorization_response_iss_parameter_supported\":$it"
        }.orEmpty()}}""",
    )
}
