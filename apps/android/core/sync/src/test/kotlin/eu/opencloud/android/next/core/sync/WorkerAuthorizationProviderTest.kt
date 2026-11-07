package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.CredentialStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.Base64

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

    @Test fun `restored basic authorization uses exact UTF8 with saved username or legacy user id fallback`() {
        listOf(
            "alice" to "secret",
            "利用者" to "秘密",
            "user😀" to "pass🔑",
            "élise" to "café",
        ).forEach { (username, password) ->
            listOf(true, false).forEach { hasSavedUsername ->
                val credentials =
                    MemoryCredentials().apply {
                        this.username = username.takeIf { hasSavedUsername }
                        this.password = password
                    }
                val provider =
                    WorkerAuthorizationProvider(
                        context,
                        credentials,
                        AccountSessions(credentials, AppClock { 1_000_000 }),
                    )
                val account = AccountEntity("basic", "https://cloud.example", username, "User", "BASIC", false)
                val header = provider.authorization(account)
                assertEquals("Basic", header.substringBefore(' '))
                assertArrayEquals(
                    "$username:$password".toByteArray(Charsets.UTF_8),
                    Base64.getDecoder().decode(header.substringAfter(' ')),
                )
                assertEquals(username.takeIf { hasSavedUsername }, credentials.username)
                assertEquals(password, credentials.password)
            }
        }
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
