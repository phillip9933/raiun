package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilityRepositoryTest {
    private val account = AccountEntity("a", "https://cloud.example", "user", "User", "OIDC", false)
    private val enabled = ServerCapabilities(null, true, true, true, false)

    @Test
    fun `concurrent refreshes coalesce and policies remain account scoped`() =
        runTest {
            var calls = 0
            var publications = 0
            val repository =
                CapabilityRepository(AppClock { 1000 }) { _, _ ->
                    calls++
                    delay(10)
                    enabled
                }
            (1..20)
                .map {
                    async {
                        repository.refresh(account, "secret") {
                            publications++
                            true
                        }
                    }
                }.awaitAll()
            assertEquals(1, calls)
            assertEquals(1, publications)
            repository.refresh(account.copy(id = "b"), "other") { true }
            assertEquals(2, calls)
        }

    @Test
    fun `failed refresh preserves published policy but fails closed and limits retries`() =
        runTest {
            var now = 1000L
            var calls = 0
            var published = enabled
            var fail = false
            val repository =
                CapabilityRepository(AppClock { now }) { _, _ ->
                    calls++
                    if (fail) throw OpenCloudException(OpenCloudError.Connectivity)
                    enabled.copy(sharingEnabled = calls == 1)
                }
            repository.refresh(account, "secret") {
                published = it
                true
            }
            now += 300_000
            fail = true
            repeat(20) {
                try {
                    repository.refresh(account, "secret") {
                        published = it
                        true
                    }
                    org.junit.Assert.fail("Stale policy must not authorize a mutation")
                } catch (failure: OpenCloudException) {
                    assertEquals(OpenCloudError.Connectivity, failure.error)
                }
            }
            assertEquals(2, calls)
            assertTrue(published.sharingEnabled)
            fail = false
            now += 30_000
            repository.refresh(account, "secret") {
                published = it
                true
            }
            assertFalse(published.sharingEnabled)
        }

    @Test
    fun `cancelled refresh is propagated and not cached`() =
        runTest {
            var calls = 0
            val repository =
                CapabilityRepository(AppClock { 1000 }) { _, _ ->
                    calls++
                    if (calls == 1) throw CancellationException()
                    enabled
                }
            try {
                repository.refresh(account, "secret") { true }
                org.junit.Assert.fail("Cancellation must escape")
            } catch (_: CancellationException) {
                // The next caller is free to refresh immediately.
            }
            repository.refresh(account, "secret") { true }
            assertEquals(2, calls)
        }
}
