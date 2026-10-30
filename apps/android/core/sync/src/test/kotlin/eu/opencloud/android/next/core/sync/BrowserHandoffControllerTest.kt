package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class BrowserHandoffControllerTest {
    @Test fun delayedGrantAfterDisposalIsClosedWithoutLaunchOrError() =
        runTest {
            val ready = CompletableDeferred<Unit>()
            val lease = WebSessionLease("fresh-browser-grant", { true }) { true }
            var launches = 0
            val errors = mutableListOf<OpenCloudError>()
            val controller =
                BrowserHandoffController(this, {
                    withContext(NonCancellable) { ready.await() }
                    lease
                }, {
                    launches++
                    true
                }, {}, errors::add, StandardTestDispatcher(testScheduler))
            controller.start()
            runCurrent()
            controller.close()
            ready.complete(Unit)
            runCurrent()
            assertEquals(0, launches)
            assertEquals(emptyList<OpenCloudError>(), errors)
            assertFalse(lease.isPermitted())
            assertThrows(OpenCloudException::class.java) { kotlinx.coroutines.runBlocking { lease.current() } }
        }

    @Test fun revokedOriginalActionCannotLaunchAfterReauthenticationWhileGrantWasPending() =
        runTest {
            val ready = CompletableDeferred<Unit>()
            var revision = 0
            val original = revision
            val lease = WebSessionLease("fresh-browser-grant", { revision == original }) { true }
            var launches = 0
            val errors = mutableListOf<OpenCloudError>()
            val controller =
                BrowserHandoffController(this, {
                    ready.await()
                    lease
                }, {
                    launches++
                    true
                }, {}, errors::add, StandardTestDispatcher(testScheduler))
            controller.start()
            runCurrent()
            revision++ // Lock/re-auth or account credential replacement advances the captured generation.
            ready.complete(Unit)
            runCurrent()
            assertEquals(0, launches)
            assertEquals(listOf(OpenCloudError.AccessDenied), errors)
        }

    @Test fun changedResourceSnapshotPreventsBrowserHandoff() =
        runTest {
            var launches = 0
            val errors = mutableListOf<OpenCloudError>()
            val controller =
                BrowserHandoffController(
                    this,
                    { WebSessionLease("fresh-browser-grant", { true }) { false } },
                    {
                        launches++
                        true
                    },
                    {},
                    errors::add,
                    StandardTestDispatcher(testScheduler),
                )
            controller.start()
            runCurrent()
            assertEquals(0, launches)
            assertEquals(listOf(OpenCloudError.AccessDenied), errors)
        }

    @Test fun finalSynchronousGuardRejectsRevocationAfterIoSnapshotValidation() =
        runTest {
            var checks = 0
            var launches = 0
            val errors = mutableListOf<OpenCloudError>()
            val controller =
                BrowserHandoffController(
                    this,
                    { WebSessionLease("fresh-browser-grant", { ++checks < 3 }) { true } },
                    {
                        launches++
                        true
                    },
                    {},
                    errors::add,
                    StandardTestDispatcher(testScheduler),
                )
            controller.start()
            runCurrent()
            assertEquals(0, launches)
            assertEquals(listOf(OpenCloudError.AccessDenied), errors)
        }

    @Test fun successfulBrowserDispatchIsSingleUseAndReleasesItsTransientGrant() =
        runTest {
            var opens = 0
            val launches = mutableListOf<String>()
            val lease = WebSessionLease("fresh-browser-grant", { true }) { true }
            val controller =
                BrowserHandoffController(
                    this,
                    {
                        opens++
                        lease
                    },
                    {
                        launches += it
                        true
                    },
                    {},
                    { error("Unexpected error") },
                    StandardTestDispatcher(testScheduler),
                )
            controller.start()
            controller.start()
            runCurrent()
            controller.start()
            runCurrent()
            assertEquals(1, opens)
            assertEquals(listOf("fresh-browser-grant"), launches)
            assertFalse(lease.isPermitted())
        }

    @Test fun missingBrowserKeepsUnavailableDistinctFromNetworkFailure() =
        runTest {
            var unavailable = 0
            val errors = mutableListOf<OpenCloudError>()
            val controller =
                BrowserHandoffController(
                    this,
                    { WebSessionLease("fresh-browser-grant", { true }) { true } },
                    { false },
                    { unavailable++ },
                    errors::add,
                    StandardTestDispatcher(testScheduler),
                )
            controller.start()
            runCurrent()
            assertEquals(1, unavailable)
            assertEquals(emptyList<OpenCloudError>(), errors)
        }
}
