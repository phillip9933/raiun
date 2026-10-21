package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.security.CredentialStore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistedSessionTest {
    @Test
    fun `basic account is restored when its password is persisted`() {
        assertTrue(hasUsablePersistedCredential(account("BASIC"), FakeCredentialStore(password = "secret"), 100))
    }

    @Test
    fun `expired oidc token is restored when it has a refresh token`() {
        val tokens = AuthTokens("expired", "refresh", 99, "Bearer", null)
        assertTrue(hasUsablePersistedCredential(account("OIDC"), FakeCredentialStore(tokens = tokens), 100))
    }

    @Test
    fun `expired oidc token without refresh token is rejected`() {
        val tokens = AuthTokens("expired", null, 99, "Bearer", null)
        assertFalse(hasUsablePersistedCredential(account("OIDC"), FakeCredentialStore(tokens = tokens), 100))
    }

    private fun account(authenticationType: String) =
        AccountEntity("account", "https://cloud.example", "alice", "Alice", authenticationType, false)

    private class FakeCredentialStore(
        private val password: String? = null,
        private val tokens: AuthTokens? = null,
    ) : CredentialStore {
        override fun saveBasicUsername(
            accountId: String,
            username: String,
        ) = Unit

        override fun readBasicUsername(accountId: String): String? = null

        override fun saveBasicPassword(
            accountId: String,
            password: String,
        ) = Unit

        override fun readBasicPassword(accountId: String): String? = password

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ) = Unit

        override fun readTokens(accountId: String): AuthTokens? = tokens

        override fun remove(accountId: String) = Unit
    }
}
