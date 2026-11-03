package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.PkceRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.AEADBadTagException

class CredentialKeyInitializationTest {
    @Test
    fun concurrentStoresShareOneCreatedKey() {
        var stored: Any? = null
        val creations = AtomicInteger()
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val results =
                (1..8).map {
                    executor.submit<Any?> {
                        check(start.await(5, TimeUnit.SECONDS))
                        CredentialKeyInitialization.obtain(
                            true,
                            { stored },
                            {
                                Any().also {
                                    stored = it
                                    creations.incrementAndGet()
                                }
                            },
                        )
                    }
                }
            start.countDown()
            val first = results.first().get(5, TimeUnit.SECONDS)
            results.forEach { assertSame(first, it.get(5, TimeUnit.SECONDS)) }
            assertEquals(1, creations.get())
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun missingKeyReadDoesNotCreateReplacement() {
        assertNull(CredentialKeyInitialization.obtain(false, { null }, { error("Must not create") }))
    }

    @Test
    fun inaccessibleExistingKeyDoesNotCreateReplacement() {
        try {
            CredentialKeyInitialization.obtain<Any>(
                true,
                { error("Unavailable") },
                {
                    fail("Must not create")
                    Any()
                },
            )
            fail("Lookup failure must propagate")
        } catch (_: IllegalStateException) {
            // The caller fails closed; an unreadable alias is never replaced.
        }
    }

    @Test
    fun diagnosticCategoriesNeverContainExceptionMessages() {
        assertEquals("authentication_failed", credentialFailureCategory(AEADBadTagException("synthetic-secret")))
        assertEquals("invalid_envelope", credentialFailureCategory(IllegalArgumentException("synthetic-secret")))
        assertEquals("key_or_crypto_unavailable", credentialFailureCategory(IllegalStateException("synthetic-secret")))
    }

    @Test
    fun authenticationModelsRedactAllFields() {
        assertEquals("AuthTokens([REDACTED])", AuthTokens("access", "refresh", 1, "type", "scope").toString())
        assertEquals("PkceRequest([REDACTED])", PkceRequest("url", "state", "verifier").toString())
    }
}
