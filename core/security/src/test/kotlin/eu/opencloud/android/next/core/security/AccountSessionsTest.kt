package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class AccountSessionsTest {
    private val credentials = MemoryCredentials()
    private val sessions = AccountSessions(credentials, AppClock { 100_000 })

    @Test fun `twenty concurrent expired requests share one committed refresh`() {
        credentials.saveTokens("account", tokens(1, "old"))
        val pool = Executors.newFixedThreadPool(20)
        try {
            val start = CountDownLatch(1)
            val refreshes = AtomicInteger()
            val requests =
                (1..20).map {
                    pool.submit<AuthTokens> {
                        check(start.await(5, TimeUnit.SECONDS))
                        sessions.tokens("account") {
                            refreshes.incrementAndGet()
                            tokens(3600, "rotated")
                        }
                    }
                }
            start.countDown()
            requests.forEach { assertEquals("rotated", it.get(5, TimeUnit.SECONDS).accessToken) }
            assertEquals(1, refreshes.get())
            assertEquals("rotated", credentials.readTokens("account")?.accessToken)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun `short lived sessions are valid until expiry without refresh permission`() {
        sessions.save("account", tokens(101, "short").copy(refreshToken = null))
        assertEquals("short", sessions.tokens("account") { error("Must not refresh") }.accessToken)
        sessions.save("account", tokens(100, "expired").copy(refreshToken = null))
        val error =
            assertThrows(OpenCloudException::class.java) {
                sessions.tokens("account") { error("Must not refresh") }
            }
        assertEquals(OpenCloudError.AuthenticationRequired, error.error)
    }

    @Test fun `removal cannot leave tokens resurrected by an in flight refresh`() {
        sessions.save("account", tokens(1, "old"))
        val pool = Executors.newFixedThreadPool(2)
        val entered = CountDownLatch(1)
        val finish = CountDownLatch(1)
        try {
            val refresh =
                pool.submit<AuthTokens> {
                    sessions.tokens("account") {
                        entered.countDown()
                        check(finish.await(5, TimeUnit.SECONDS))
                        tokens(3600, "new")
                    }
                }
            check(entered.await(5, TimeUnit.SECONDS))
            val remove = pool.submit { sessions.remove("account") }
            finish.countDown()
            refresh.get(5, TimeUnit.SECONDS)
            remove.get(5, TimeUnit.SECONDS)
            assertNull(credentials.readTokens("account"))
        } finally {
            finish.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun `invalid grant clears unusable credentials instead of causing a refresh storm`() {
        sessions.save("account", tokens(1, "old"))
        val refreshes = AtomicInteger()
        repeat(20) {
            assertThrows(OpenCloudException::class.java) {
                sessions.tokens("account") {
                    refreshes.incrementAndGet()
                    throw OpenCloudException(OpenCloudError.AuthenticationRequired)
                }
            }
        }
        assertEquals(1, refreshes.get())
    }

    @Test fun `credential lease closes on removal and cannot revive with the same account id`() {
        sessions.save("account", tokens(3600, "first"))
        val original = sessions.beginLease("account")
        assertTrue(original())
        sessions.remove("account")
        assertFalse(original())
        assertFalse(sessions.beginLease("account")())
        sessions.save("account", tokens(3600, "second"))
        assertFalse(original())
        assertTrue(sessions.beginLease("account")())
    }

    private fun tokens(
        expiry: Long,
        access: String,
    ) = AuthTokens(access, "refresh", expiry, "Bearer", null)

    private class MemoryCredentials : CredentialStore {
        private val tokens = ConcurrentHashMap<String, AuthTokens>()

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ) {
            this.tokens[accountId] = tokens
        }

        override fun readTokens(accountId: String) = tokens[accountId]

        override fun remove(accountId: String) {
            tokens.remove(accountId)
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
    }
}
