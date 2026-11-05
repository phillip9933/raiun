package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EncryptedFolderDiscoveryLifecycleTest {
    @Test fun `account invalidation rejects late noncooperative cached roots without a new Space`() =
        runBlocking {
            val admissionThread = AtomicReference<Thread>()
            val dispatcher =
                Executors
                    .newSingleThreadExecutor { task ->
                        Thread(task, "encrypted-discovery-main").also { admissionThread.set(it) }
                    }.asCoroutineDispatcher()
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val finished = CompletableDeferred<Unit>()
            val application = RuntimeEnvironment.getApplication()
            val updates = CopyOnWriteArrayList<List<VaultLocation>>()
            val root =
                VaultLocation(
                    "a",
                    "private",
                    VaultLocationKind.FOLDER_VAULT,
                    "space",
                    "vault",
                    "root",
                    "https://cloud.example",
                    "https://cloud.example/dav",
                    "private",
                    true,
                )
            val discovery =
                EncryptedFolderDiscovery(
                    application,
                    FileBrowserStore(FileBrowserDatabase.create(application)),
                    scope,
                    reads = { _, _, _, cached ->
                        started.complete(Unit)
                        withContext(NonCancellable) {
                            release.await()
                            // This callback deliberately outlives job cancellation, so generation fencing is required.
                            cached(listOf(root))
                            finished.complete(Unit)
                        }
                        listOf(root)
                    },
                    mainDispatcher = dispatcher,
                    update = { roots, _ ->
                        assertSame(admissionThread.get(), Thread.currentThread())
                        updates += roots
                    },
                )
            try {
                withContext(dispatcher) { discovery.refresh("a", "space", null) }
                withTimeout(5000) { started.await() }
                // Simulate A -> B -> A. Neither new load has a Space to trigger refresh.
                withContext(dispatcher) {
                    discovery.invalidate()
                    discovery.invalidate()
                }
                release.complete(Unit)
                withTimeout(5000) { finished.await() }
                assertTrue(updates.isNotEmpty())
                assertTrue(updates.all { it.isEmpty() })
            } finally {
                release.complete(Unit)
                scope.cancel()
                dispatcher.close()
            }
        }
}
