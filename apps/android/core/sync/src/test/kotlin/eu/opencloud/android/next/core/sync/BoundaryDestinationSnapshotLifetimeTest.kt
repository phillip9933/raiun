package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BoundaryDestinationSnapshotLifetimeTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun emptyChooserStillChecksRevokedGuardAndRefusesClosedReads() =
        runBlocking<Unit> {
            var allowed = true
            val snapshot =
                captureBoundaryDestinationFolders(context, "", {
                    if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied)
                }) { }
            assertEquals(0L, snapshot.totalCount)
            allowed = false
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
            assertEquals(OpenCloudError.AccessDenied, failure.error)
            snapshot.close()
            val closed = captureBoundaryDestinationFolders(context, "", {}) { }
            closed.close()
            assertThrows(OpenCloudException::class.java) { runBlocking { closed.page() } }
        }

    @Test fun suspendedProducerMayResumeOnAnotherThreadWithoutOwningASqliteTransaction() =
        runBlocking<Unit> {
            val first = BoundaryDestinationFolder("one", "parent/one", "one", false)
            val second = BoundaryDestinationFolder("two", "parent/two", "two", true)
            withTimeout(5_000) {
                captureBoundaryDestinationFolders(context, "parent", {}) { emit ->
                    emit(first)
                    withContext(Dispatchers.Default) { emit(second) }
                }.use { snapshot ->
                    assertEquals(2L, snapshot.totalCount)
                    assertEquals(listOf(first, second), snapshot.page())
                }
            }
        }

    @Test fun cancellationWhileFinalGuardIsSuspendedNeverReturnsAnIndexAndClosesOwnedStages() =
        runBlocking<Unit> {
            val before = stages()
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var checks = 0
            val building =
                async {
                    captureBoundaryDestinationFolders(context, "", {
                        if (++checks == 2) {
                            entered.complete(Unit)
                            withContext(NonCancellable) { release.await() }
                        }
                    }) { emit -> emit(BoundaryDestinationFolder("one", "one", "one", true)) }
                }
            try {
                withTimeout(5_000) { entered.await() }
                building.cancel()
                release.complete(Unit)
                withTimeout(5_000) { building.join() }
                assertThrows(CancellationException::class.java) { runBlocking { building.await() } }
                assertEquals(before, stages())
            } finally {
                release.complete(Unit)
                building.cancel()
            }
        }

    private fun stages(): Set<String> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("vault-directory-") || it.name.startsWith("backup-traversal-") }
            .map { it.name }
            .toSet()
}
