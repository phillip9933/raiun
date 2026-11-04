package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.CredentialStore
import okhttp3.Credentials
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class WorkerAuthorizationProviderTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun `saved unexpired bearer tokens use canonical header without refresh`() {
        listOf("bearer", "BEARER", "bEaReR").forEachIndexed { index, tokenType ->
            val credentials = MemoryCredentials()
            val tokens = AuthTokens("AaZ9._~-+Opaque=", "refresh", 2_000, tokenType, null)
            credentials.saveTokens("account-$index", tokens)
            val sessions = AccountSessions(credentials, AppClock { 1_000_000 })
            val provider = WorkerAuthorizationProvider(context, credentials, sessions)

            assertEquals("Bearer ${tokens.accessToken}", provider.authorization(oidcAccount("account-$index")))
            assertEquals(tokens, credentials.readTokens("account-$index"))
        }
    }

    @Test fun `unsupported saved scheme fails without replacing stored credentials`() {
        val credentials = MemoryCredentials()
        val tokens = AuthTokens("opaque", "refresh", 2_000, "MAC", null)
        credentials.saveTokens("account", tokens)
        val provider =
            WorkerAuthorizationProvider(context, credentials, AccountSessions(credentials, AppClock { 1_000_000 }))

        val failure = assertThrows(OpenCloudException::class.java) { provider.authorization(oidcAccount("account")) }

        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(tokens, credentials.readTokens("account"))
    }

    @Test fun `basic authorization stays unchanged`() {
        val credentials =
            MemoryCredentials().apply {
                username = "alice"
                password = "secret"
            }
        val provider =
            WorkerAuthorizationProvider(context, credentials, AccountSessions(credentials, AppClock { 1_000_000 }))

        assertEquals(
            Credentials.basic("alice", "secret"),
            provider.authorization(AccountEntity("basic", "https://cloud.example", "user", "User", "BASIC", false)),
        )
    }

    private fun oidcAccount(id: String) = AccountEntity(id, "https://cloud.example", "user", "User", "OIDC", false)

    private class MemoryCredentials : CredentialStore {
        private val tokens = mutableMapOf<String, AuthTokens>()
        var username: String? = null
        var password: String? = null

        override fun saveBasicUsername(
            accountId: String,
            username: String,
        ) {
            this.username = username
        }

        override fun readBasicUsername(accountId: String): String? = username

        override fun saveBasicPassword(
            accountId: String,
            password: String,
        ) {
            this.password = password
        }

        override fun readBasicPassword(accountId: String): String? = password

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ) {
            this.tokens[accountId] = tokens
        }

        override fun readTokens(accountId: String): AuthTokens? = tokens[accountId]

        override fun remove(accountId: String) {
            tokens.remove(accountId)
        }
    }
}
