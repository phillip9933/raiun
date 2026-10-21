package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class EmbeddedHostControllerTest {
    @Test fun `owner cancellation tears down even before the first dispatch`() =
        runTest {
            for (cancelFirst in listOf(false, true)) {
                val parent = Job()
                val dispatcher = StandardTestDispatcher(testScheduler)
                val surface = Surface()
                val errors = mutableListOf<OpenCloudError>()
                val host =
                    EmbeddedHostController(
                        CoroutineScope(parent + dispatcher),
                        surface,
                        { WebSessionLease("secret", { true }) { true } },
                        errors::add,
                        dispatcher,
                    )
                if (cancelFirst) parent.cancel()
                host.start()
                parent.cancel()
                runCurrent()
                assertEquals(1, surface.closed)
                if (cancelFirst) assertEquals(emptyList<String>(), surface.shown)
                assertEquals(emptyList<OpenCloudError>(), errors)
            }
        }

    @Test fun `host opens once and tears down permanently on revocation`() =
        runTest {
            val surface = Surface()
            val errors = mutableListOf<OpenCloudError>()
            var allowed = true
            val lease = WebSessionLease("secret", { allowed }) { true }
            val host =
                EmbeddedHostController(this, surface, { lease }, errors::add, StandardTestDispatcher(testScheduler))
            host.start()
            host.start()
            runCurrent()
            assertEquals(listOf("secret"), surface.shown)
            allowed = false
            advanceTimeBy(1000)
            runCurrent()
            assertEquals(listOf(OpenCloudError.AccessDenied), errors)
            assertEquals(1, surface.closed)
            allowed = true
            host.start()
            runCurrent()
            assertEquals(1, surface.shown.size)
        }

    @Test fun `background close cancels late preparation without displaying or leaking it`() =
        runTest {
            val surface = Surface()
            val release = CompletableDeferred<Unit>()
            val lease = WebSessionLease("secret", { true }) { true }
            val errors = mutableListOf<OpenCloudError>()
            val host =
                EmbeddedHostController(this, surface, {
                    withContext(NonCancellable) { release.await() }
                    lease
                }, errors::add, StandardTestDispatcher(testScheduler))
            host.start()
            runCurrent()
            host.close()
            release.complete(Unit)
            runCurrent()
            assertEquals(emptyList<String>(), surface.shown)
            assertEquals(1, surface.closed)
            assertEquals(emptyList<OpenCloudError>(), errors)
            assertThrows(OpenCloudException::class.java) { kotlinx.coroutines.runBlocking { lease.current() } }
        }

    @Test fun `failed rendering closes the surface and sanitizes the failure`() =
        runTest {
            val errors = mutableListOf<OpenCloudError>()
            var closed = 0
            val surface =
                object : EmbeddedSessionSurface<String> {
                    override fun show(session: String) {
                        error("private delegated token")
                    }

                    override fun close() {
                        closed++
                    }
                }
            val host =
                EmbeddedHostController(
                    this,
                    surface,
                    { WebSessionLease("secret", { true }) { true } },
                    errors::add,
                    StandardTestDispatcher(testScheduler),
                )
            host.start()
            runCurrent()
            assertEquals(listOf(OpenCloudError.Unknown), errors)
            assertEquals(1, closed)
            host.close()
            assertEquals(1, closed)
        }

    @Test fun `closed host cannot start or report cancellation as an error`() =
        runTest {
            val surface = Surface()
            var opened = false
            val errors = mutableListOf<OpenCloudError>()
            val host =
                EmbeddedHostController(this, surface, {
                    opened = true
                    WebSessionLease("secret", { true }) { true }
                }, errors::add, StandardTestDispatcher(testScheduler))
            host.close()
            host.start()
            runCurrent()
            assertEquals(false, opened)
            assertEquals(1, surface.closed)
            assertEquals(emptyList<OpenCloudError>(), errors)
        }

    private class Surface : EmbeddedSessionSurface<String> {
        val shown = mutableListOf<String>()
        var closed = 0

        override fun show(session: String) {
            shown += session
        }

        override fun close() {
            closed++
        }
    }
}
