package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.CredentialStore
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ClientRegistrationResolverTest {
    private lateinit var server: MockWebServer
    private lateinit var api: OpenCloudApi
    private val credentials = RegistrationCredentials()

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `advertised client takes precedence over DCR and is used by PKCE`() {
        val resolver = ClientRegistrationResolver(api, credentials)
        val chosen = resolver.resolve("https://cloud.example", configuration().copy(clientId = "advertised"))
        assertEquals("advertised", chosen.clientId)
        assertEquals(0, server.requestCount)
        assertTrue(AuthRepository(api, credentials).beginPkce(chosen).authorizationUrl.contains("client_id=advertised"))
    }

    @Test fun `cached DCR binding survives resolver recreation and cannot cross servers`() {
        server.enqueue(MockResponse().setResponseCode(201).setBody(response("one")))
        server.enqueue(MockResponse().setResponseCode(201).setBody(response("two")))
        val first = ClientRegistrationResolver(api, credentials).resolve("https://cloud.example", configuration())
        assertEquals(
            first,
            ClientRegistrationResolver(api, credentials).resolve("https://cloud.example", configuration()),
        )
        assertEquals(
            "two",
            ClientRegistrationResolver(api, credentials)
                .resolve("https://other.example", configuration())
                .clientId,
        )
        assertEquals(2, server.requestCount)
    }

    @Test fun `static client requires explicit configuration and does not mask failed DCR`() {
        val resolver = ClientRegistrationResolver(api, credentials)
        val static = configuration().copy(registrationEndpoint = null)
        val missing = assertThrows(OpenCloudException::class.java) { resolver.resolve("https://cloud.example", static) }
        assertEquals(eu.opencloud.android.next.core.network.OpenCloudError.ClientRegistrationRequired, missing.error)
        assertEquals("configured", resolver.resolve("https://cloud.example", static, "configured").clientId)
        server.enqueue(MockResponse().setResponseCode(403).setBody("software statement required"))
        assertThrows(OpenCloudException::class.java) {
            resolver.resolve("https://cloud.example", configuration(), "must-not-fallback")
        }
        assertEquals(1, server.requestCount)
    }

    @Test fun `corrected static client replaces cached rejected client and reaches authorization request`() {
        val config = configuration().copy(registrationEndpoint = null)
        ClientRegistrationResolver(api, credentials).resolve("https://cloud.example", config, "wrong-client")
        val corrected =
            ClientRegistrationResolver(
                api,
                credentials,
            ).resolve("https://cloud.example", config, "OpenCloudAndroid")
        assertEquals("OpenCloudAndroid", corrected.clientId)
        assertTrue(
            AuthRepository(
                api,
                credentials,
            ).beginPkce(corrected).authorizationUrl.contains("client_id=OpenCloudAndroid"),
        )
        assertEquals(
            "OpenCloudAndroid",
            ClientRegistrationResolver(api, credentials).resolve("https://cloud.example", config).clientId,
        )
        assertEquals(
            "OpenCloudAndroid",
            ClientRegistrationResolver(api, credentials).bindingForSession("https://cloud.example", corrected).clientId,
        )
        assertEquals(0, server.requestCount)
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

    private fun response(clientId: String) =
        """{"client_id":"$clientId","redirect_uris":["$NEXT_OIDC_REDIRECT_URI"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}"""

    private class RegistrationCredentials : CredentialStore {
        private val registrations = mutableMapOf<String, OidcClientRegistration>()

        override fun readClientRegistration(key: String) = registrations[key]

        override fun saveClientRegistration(
            key: String,
            registration: OidcClientRegistration,
        ) {
            registrations[key] = registration
        }

        override fun saveBasicUsername(
            accountId: String,
            username: String,
        ) = Unit

        override fun readBasicUsername(accountId: String): String? = null

        override fun saveBasicPassword(
            accountId: String,
            password: String,
        ) = Unit

        override fun readBasicPassword(accountId: String): String? = null

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ) = Unit

        override fun readTokens(accountId: String): AuthTokens? = null

        override fun remove(accountId: String) = Unit
    }
}
