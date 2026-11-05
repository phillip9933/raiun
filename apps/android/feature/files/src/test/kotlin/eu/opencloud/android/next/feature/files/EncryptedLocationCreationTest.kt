package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.concurrent.Executors

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EncryptedLocationCreationTest {
    @Test fun `successful creation carries original binding and wipes accepted and rejected passwords`() =
        runBlocking {
            Fixture().use { fixture ->
                val first = fixture.onMain { fixture.context.beginAccount("a") }
                val password = "secret".toCharArray()
                fixture.onMain { fixture.creation.folder(first, "space", null, "vault", password) }
                assertTrue(password.all { it == '\u0000' })
                val captured = withTimeout(5000) { fixture.started.await() }
                val rejected = "other".toCharArray()
                fixture.onMain {
                    fixture.context.beginAccount("b")
                    fixture.context.beginAccount("a")
                    fixture.creation.space(fixture.context.binding!!, "second", rejected)
                }
                assertTrue(rejected.all { it == '\u0000' })
                fixture.result.complete(root)
                withTimeout(5000) { fixture.finished.await() }
                assertEquals(first, fixture.createdBinding)
                assertTrue(captured.all { it == '\u0000' })
                assertEquals(listOf(true, false), fixture.busy)
                assertEquals(1, fixture.calls)
            }
        }

    @Test fun `ambiguous failure carries captured binding and wipes owned password`() =
        runBlocking {
            Fixture().use { fixture ->
                val first = fixture.onMain { fixture.context.beginAccount("a") }
                val password = "secret".toCharArray()
                fixture.onMain { fixture.creation.space(first, "vault", password) }
                val captured = withTimeout(5000) { fixture.started.await() }
                fixture.onMain {
                    fixture.context.beginAccount("b")
                    fixture.context.beginAccount("a")
                }
                fixture.result.completeExceptionally(IllegalStateException("synthetic"))
                withTimeout(5000) { fixture.finished.await() }
                assertEquals(first, fixture.uncertainBinding)
                assertTrue(password.all { it == '\u0000' })
                assertTrue(captured.all { it == '\u0000' })
                assertEquals(listOf(true, false), fixture.busy)
                assertEquals(1, fixture.calls)
            }
        }

    @Test fun `cancellation during backend wipes owned password without result callback`() =
        runBlocking {
            Fixture().use { fixture ->
                val binding = fixture.onMain { fixture.context.beginAccount("a") }
                val password = "secret".toCharArray()
                fixture.onMain { fixture.creation.space(binding, "vault", password) }
                val captured = withTimeout(5000) { fixture.started.await() }
                fixture.cancel()
                withTimeout(5000) { fixture.finished.await() }
                assertTrue(password.all { it == '\u0000' })
                assertTrue(captured.all { it == '\u0000' })
                assertEquals(null, fixture.createdBinding)
                assertEquals(null, fixture.uncertainBinding)
                assertEquals(listOf(true, false), fixture.busy)
            }
        }

    private class Fixture : AutoCloseable {
        private val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        private val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val context = BrowserAccountContext(dispatcher)
        val started = CompletableDeferred<CharArray>()
        val result = CompletableDeferred<VaultLocation>()
        val finished = CompletableDeferred<Unit>()
        val busy = mutableListOf<Boolean>()
        var createdBinding: BrowserAccountBinding? = null
        var uncertainBinding: BrowserAccountBinding? = null
        var calls = 0
        private val backend =
            object : EncryptedCreationBackend {
                override suspend fun folder(
                    account: String,
                    drive: String,
                    parent: String?,
                    name: String,
                    password: CharArray,
                ): VaultLocation = execute(password)

                override suspend fun space(
                    account: String,
                    name: String,
                    password: CharArray,
                ): VaultLocation = execute(password)

                private suspend fun execute(password: CharArray): VaultLocation {
                    calls++
                    started.complete(password)
                    return result.await()
                }
            }
        private val application = RuntimeEnvironment.getApplication()
        val creation =
            EncryptedLocationCreation(
                application,
                FileBrowserStore(FileBrowserDatabase.create(application)),
                scope,
                onBusy = { value ->
                    busy += value
                    if (!value) finished.complete(Unit)
                },
                onCreated = { binding, _, _ -> createdBinding = binding },
                onUncertain = { binding -> uncertainBinding = binding },
                backend = backend,
                ioDispatcher = Dispatchers.IO,
            )

        suspend fun <T> onMain(action: () -> T): T = withContext(dispatcher) { action() }

        fun cancel() = scope.cancel()

        override fun close() {
            scope.cancel()
            dispatcher.close()
        }
    }

    private companion object {
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
    }
}
