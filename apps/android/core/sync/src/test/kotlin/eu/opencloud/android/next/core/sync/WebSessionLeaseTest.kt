package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class WebSessionLeaseTest {
    @Test fun `closed or revoked sessions never revive`() =
        runBlocking<Unit> {
            var allowed = true
            val lease = WebSessionLease("secret", { allowed }) { true }
            assertEquals("secret", lease.current())
            assertEquals("WebSessionLease(redacted)", lease.toString())
            allowed = false
            assertThrows(OpenCloudException::class.java) { runBlocking { lease.current() } }
            allowed = true
            assertThrows(OpenCloudException::class.java) { runBlocking { lease.current() } }
            val closed = WebSessionLease("secret", { true }) { true }
            closed.close()
            assertThrows(OpenCloudException::class.java) { runBlocking { closed.current() } }
        }

    @Test fun `closing during an identity check prevents late publication`() =
        runBlocking {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val lease =
                WebSessionLease("secret", { true }) {
                    entered.complete(Unit)
                    release.await()
                    true
                }
            val result =
                async {
                    try {
                        lease.current()
                        null
                    } catch (failure: OpenCloudException) {
                        failure.error
                    }
                }
            entered.await()
            lease.close()
            release.complete(Unit)
            assertEquals(OpenCloudError.AccessDenied, result.await())
        }

    @Test fun `changed identity and failed validation permanently clear the payload`() =
        runBlocking<Unit> {
            var current = false
            val lease = WebSessionLease("secret", { true }) { current }
            assertThrows(OpenCloudException::class.java) { runBlocking { lease.current() } }
            current = true
            assertThrows(OpenCloudException::class.java) { runBlocking { lease.current() } }
            val failed = WebSessionLease("secret", { true }) { error("private account data") }
            val error = assertThrows(OpenCloudException::class.java) { runBlocking { failed.current() } }
            assertEquals(OpenCloudError.Unknown, error.error)
        }

    @Test fun `cancellation retains its identity and invalidates the session`() =
        runBlocking<Unit> {
            val cancelled = CancellationException("cancelled")
            var first = true
            val lease = WebSessionLease("secret", { true }) { if (first) throw cancelled else true }
            assertSame(cancelled, assertThrows(CancellationException::class.java) { runBlocking { lease.current() } })
            first = false
            assertThrows(OpenCloudException::class.java) { runBlocking { lease.current() } }
        }
}
