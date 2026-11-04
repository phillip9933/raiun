package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.security.CredentialStore
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class AuthRepositoryPersistenceTest {
    private lateinit var server: MockWebServer
    private lateinit var credentials: RecordingCredentials
    private lateinit var repository: AuthRepository

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        credentials = RecordingCredentials()
        val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
        repository = AuthRepository(api, credentials)
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `basic credentials are not saved when capabilities validation fails`() {
        server.enqueue(MockResponse().setBody(PROFILE))
        server.enqueue(MockResponse().setResponseCode(503))

        assertThrows(TransferHttpException::class.java) {
            repository.loginBasic(server.url("/").toString().trimEnd('/'), "alice", "secret")
        }

        assertNull(credentials.basicPassword)
        assertEquals(2, server.requestCount)
    }

    @Test fun `basic credentials are saved after capabilities validation succeeds`() {
        server.enqueue(MockResponse().setBody(PROFILE))
        server.enqueue(MockResponse().setBody(CAPABILITIES))

        repository.loginBasic(server.url("/").toString().trimEnd('/'), "alice", "secret")

        assertEquals("secret", credentials.basicPassword)
        assertEquals(2, server.requestCount)
    }

    @Test fun `oidc tokens are not saved when capabilities validation fails`() {
        val serverUrl = server.url("/").toString().trimEnd('/')
        val config =
            ClientRegistrationResolver(
                OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true)),
                credentials,
            ).resolve(
                serverUrl,
                OidcConfiguration(
                    serverUrl,
                    "$serverUrl/authorize",
                    "$serverUrl/token",
                    null,
                    "client",
                    listOf("openid"),
                ),
            )
        server.enqueue(
            MockResponse().setBody("""{"access_token":"access","refresh_token":"refresh","token_type":"bearer"}"""),
        )
        server.enqueue(MockResponse().setBody(PROFILE))
        server.enqueue(MockResponse().setResponseCode(503))

        assertThrows(TransferHttpException::class.java) {
            repository.completePkce(serverUrl, config, "code", "verifier")
        }

        assertNull(credentials.tokens)
        assertNull(credentials.sessionRegistration)
        assertEquals(3, server.requestCount)
    }

    @Test fun `pending legacy basic account rejects credential replacement after valid metadata`() {
        val serverUrl = server.url("/Team").toString().trimEnd('/')
        val legacyId = "${serverUrl.lowercase()}#alice"
        credentials.basicPassword = "existing-password"
        val previousTokens = AuthTokens("existing-access", "existing-refresh", Long.MAX_VALUE, "Bearer", null)
        credentials.tokens = previousTokens
        val admitted = mutableListOf<String>()
        repository =
            AuthRepository(
                OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true)),
                credentials,
                savedAccountIdentity = { id ->
                    assertEquals(legacyId, id)
                    // This stored identity remains available even when pending removal hides the active row.
                    serverUrl to "alice"
                },
                canSaveAccount = { id ->
                    admitted.add(id)
                    false
                },
            )
        server.enqueue(MockResponse().setBody(PROFILE))
        server.enqueue(MockResponse().setBody(CAPABILITIES))

        val failure =
            assertThrows(AccountRemovalPendingException::class.java) {
                repository.loginBasic(serverUrl, "alice", "replacement-password")
            }

        assertEquals("Account cleanup pending.", failure.message)
        assertEquals(listOf(legacyId), admitted)
        assertEquals(2, server.requestCount)
        assertEquals("existing-password", credentials.basicPassword)
        assertEquals(previousTokens, credentials.tokens)
        assertEquals(0, credentials.credentialWrites)
        assertEquals(0, credentials.removals)
    }

    @Test fun `pending oidc account rejects token replacement after valid metadata`() {
        val serverUrl = server.url("/").toString().trimEnd('/')
        val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
        val config =
            ClientRegistrationResolver(api, credentials).resolve(
                serverUrl,
                OidcConfiguration(
                    serverUrl,
                    "$serverUrl/authorize",
                    "$serverUrl/token",
                    null,
                    "client",
                    listOf("openid"),
                ),
            )
        val previousTokens = AuthTokens("existing-access", "existing-refresh", Long.MAX_VALUE, "Bearer", null)
        credentials.tokens = previousTokens
        credentials.basicPassword = "existing-password"
        val previousRegistration =
            OidcClientRegistration(
                serverUrl,
                serverUrl,
                "existing-client",
                eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI,
                "$serverUrl/authorize",
                "$serverUrl/token",
                ClientRegistrationSource.STATIC,
            )
        credentials.sessionRegistration = previousRegistration
        val admitted = mutableListOf<String>()
        repository =
            AuthRepository(
                api,
                credentials,
                canSaveAccount = { id ->
                    admitted.add(id)
                    false
                },
            )
        server.enqueue(
            MockResponse().setBody(
                """{"access_token":"replacement","refresh_token":"replacement-refresh","token_type":"bearer"}""",
            ),
        )
        server.enqueue(MockResponse().setBody(PROFILE))
        server.enqueue(MockResponse().setBody(CAPABILITIES))

        val failure =
            assertThrows(AccountRemovalPendingException::class.java) {
                repository.completePkce(serverUrl, config, "code", "verifier")
            }

        assertEquals("Account cleanup pending.", failure.message)
        assertEquals(listOf(resolveAccountId(serverUrl, "alice") { null }), admitted)
        assertEquals(3, server.requestCount)
        assertEquals(previousTokens, credentials.tokens)
        assertEquals("existing-password", credentials.basicPassword)
        assertEquals(previousRegistration, credentials.sessionRegistration)
        assertEquals(0, credentials.credentialWrites)
        assertEquals(0, credentials.removals)
    }

    @Test fun `unsupported token scheme stops initial login before protected requests`() {
        val serverUrl = server.url("/").toString().trimEnd('/')
        val config =
            ClientRegistrationResolver(
                OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true)),
                credentials,
            ).resolve(
                serverUrl,
                OidcConfiguration(
                    serverUrl,
                    "$serverUrl/authorize",
                    "$serverUrl/token",
                    null,
                    "client",
                    listOf("openid"),
                ),
            )
        server.enqueue(MockResponse().setBody("""{"access_token":"opaque","token_type":"MAC"}"""))

        val failure =
            assertThrows(OpenCloudException::class.java) {
                repository.completePkce(serverUrl, config, "code", "verifier")
            }

        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(1, server.requestCount)
        assertNull(credentials.tokens)
        assertNull(credentials.sessionRegistration)
    }

    private class RecordingCredentials : CredentialStore {
        var credentialWrites = 0
        var removals = 0
        var basicPassword: String? = null
        var tokens: AuthTokens? = null
        var sessionRegistration: OidcClientRegistration? = null
        private val registrations = mutableMapOf<String, OidcClientRegistration>()

        override fun saveBasicCredentials(
            accountId: String,
            username: String,
            password: String,
        ) {
            credentialWrites++
            basicPassword = password
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

        override fun readBasicPassword(accountId: String): String? = basicPassword

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ) {
            credentialWrites++
            this.tokens = tokens
        }

        override fun readTokens(accountId: String): AuthTokens? = tokens

        override fun readClientRegistration(key: String): OidcClientRegistration? = registrations[key]

        override fun saveClientRegistration(
            key: String,
            registration: OidcClientRegistration,
        ) {
            registrations[key] = registration
        }

        override fun saveRegisteredTokens(
            accountId: String,
            tokens: AuthTokens,
            registration: OidcClientRegistration,
        ) {
            credentialWrites++
            this.tokens = tokens
            sessionRegistration = registration
        }

        override fun remove(accountId: String) {
            removals++
            basicPassword = null
            tokens = null
            sessionRegistration = null
        }
    }

    private companion object {
        const val PROFILE = """{"ocs":{"data":{"id":"alice","display-name":"Alice"}}}"""
        const val CAPABILITIES = """{"ocs":{"data":{"capabilities":{}}}}"""
    }
}
