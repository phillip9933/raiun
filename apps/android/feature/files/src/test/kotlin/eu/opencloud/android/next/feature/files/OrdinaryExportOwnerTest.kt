package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class OrdinaryExportOwnerTest {
    @Test fun `accepted export retains original source and gate across account roundtrip`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val job = fixture.onMain { requireNotNull(fixture.export(removeLocal = true)) }
                val prepare = fixture.nextPreparation()
                val ready = prepare.resource.copy(name = "Prepared", localPath = "/synthetic/prepared")
                fixture.account("b")
                assertNull(fixture.onMain { fixture.export() })
                fixture.account("a")
                assertNull(fixture.onMain { fixture.export() })
                prepare.result.complete(ready)
                val export = fixture.nextExport()
                assertSame(ready, export.resource)
                assertEquals(fixture.destination, export.destination)
                assertNull(fixture.ui.exportStatus)
                export.result.complete(Unit)
                withTimeout(5000) { job.join() }
                assertEquals(listOf(Triple("a", "space", "file")), fixture.reads)
                assertEquals(listOf(ready), fixture.removed)
                assertNull(fixture.ui.exportStatus)
                assertFalse(fixture.ui.exporting)
                val retry = fixture.onMain { requireNotNull(fixture.export()) }
                fixture.nextPreparation().result.completeExceptionally(IllegalStateException("synthetic failure"))
                withTimeout(5000) { retry.join() }
            }
        }

    @Test fun `late export failure cannot replace another account status`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val job = fixture.onMain { requireNotNull(fixture.export(removeLocal = true)) }
                val prepare = fixture.nextPreparation()
                prepare.result.complete(prepare.resource)
                val export = fixture.nextExport()
                fixture.account("b")
                fixture.onMain { fixture.ui = fixture.ui.copy(exportStatus = "Current account status") }
                export.result.completeExceptionally(IllegalStateException("synthetic provider details"))
                withTimeout(5000) { job.join() }
                assertEquals("Current account status", fixture.ui.exportStatus)
                assertFalse(fixture.ui.exporting)
                assertTrue(fixture.removed.isEmpty())
            }
        }

    @Test fun `cancelled preparation cannot export and releases gate through noncancellable finalization`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val job = fixture.onMain { requireNotNull(fixture.export(removeLocal = true)) }
                val prepare = fixture.nextPreparation()
                job.cancel()
                assertNull(fixture.onMain { fixture.export() })
                prepare.result.complete(prepare.resource)
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertFalse(fixture.ui.exporting)
                assertEquals("Preparing export…", fixture.ui.exportStatus)
                assertTrue(fixture.exports.tryReceive().isFailure)
                assertTrue(fixture.removed.isEmpty())
                val retry = fixture.onMain { requireNotNull(fixture.export()) }
                val retryPreparation = fixture.nextPreparation()
                retryPreparation.result.complete(retryPreparation.resource)
                fixture.nextExport().result.complete(Unit)
                withTimeout(5000) { retry.join() }
                assertEquals("Saved to the selected location.", fixture.ui.exportStatus)
            }
        }

    @Test fun `cancelled provider write keeps local copy and releases gate`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val job = fixture.onMain { requireNotNull(fixture.export(removeLocal = true)) }
                val prepare = fixture.nextPreparation()
                prepare.result.complete(prepare.resource)
                fixture.nextExport()
                job.cancel()
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertFalse(fixture.ui.exporting)
                assertTrue(fixture.removed.isEmpty())
            }
        }

    @Test fun `provider failure keeps local copy and publishes bounded failure`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val job = fixture.onMain { requireNotNull(fixture.export(removeLocal = true)) }
                val prepare = fixture.nextPreparation()
                prepare.result.complete(prepare.resource)
                fixture.nextExport().result.completeExceptionally(IllegalStateException("synthetic provider details"))
                withTimeout(5000) { job.join() }
                assertEquals(
                    "Export did not finish. Your cloud file is unchanged. Check the destination before retrying.",
                    fixture.ui.exportStatus,
                )
                assertTrue(fixture.removed.isEmpty())
                assertFalse(fixture.ui.exporting)
            }
        }

    @Test fun `external preparation rejects retained resource before IO and after account roundtrip`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("b")
                fixture.assertPreparationCancelled()
                assertTrue(fixture.preparations.tryReceive().isFailure)
                fixture.account("a")
                val result = fixture.scope.async { runCatching { fixture.owner.prepareExternalFile(resource()) } }
                val prepare = fixture.nextPreparation()
                fixture.account("b")
                fixture.account("a")
                prepare.result.complete(prepare.resource)
                assertTrue(withTimeout(5000) { result.await() }.exceptionOrNull() is CancellationException)
                assertTrue(fixture.exports.tryReceive().isFailure)
            }
        }

    @Test fun `cancelled noncooperative external preparation does not return prepared resource`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account("a")
                val returned = CompletableDeferred<ResourceEntity>()
                val job = fixture.scope.launch { returned.complete(fixture.owner.prepareExternalFile(resource())) }
                val prepare = fixture.nextPreparation()
                job.cancel()
                prepare.result.complete(prepare.resource)
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertFalse(returned.isCompleted)
            }
        }

    private class Fixture : AutoCloseable {
        private val admissionThread = AtomicReference<Thread>()
        private val dispatcher =
            Executors
                .newSingleThreadExecutor { task ->
                    Thread(task, "export-admission").also { admissionThread.set(it) }
                }.asCoroutineDispatcher()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val accountContext = BrowserAccountContext(dispatcher)
        var ui = FileBrowserUiState()
        val destination: Uri = Uri.parse("content://synthetic.provider/export")
        val preparations = Channel<Preparation>(Channel.UNLIMITED)
        val exports = Channel<Export>(Channel.UNLIMITED)
        val reads = CopyOnWriteArrayList<Triple<String, String, String>>()
        val removed = CopyOnWriteArrayList<ResourceEntity>()
        val owner =
            OrdinaryExportOwner(
                scope = scope,
                accountContext = accountContext,
                files =
                    object : OrdinaryExportFiles {
                        override suspend fun resource(
                            account: String,
                            space: String,
                            id: String,
                        ): ResourceEntity {
                            reads += Triple(account, space, id)
                            return resource().copy(accountId = account, spaceId = space, remoteId = id)
                        }

                        override suspend fun prepare(resource: ResourceEntity): ResourceEntity {
                            val request = Preparation(resource)
                            preparations.send(request)
                            // Cache preparation may finish after the request was cancelled.
                            return withContext(NonCancellable) { request.result.await() }
                        }

                        override suspend fun export(
                            resource: ResourceEntity,
                            destination: Uri,
                        ) {
                            val request = Export(resource, destination)
                            exports.send(request)
                            request.result.await()
                        }

                        override suspend fun removeLocalCopy(resource: ResourceEntity) {
                            removed += resource
                        }
                    },
                reduce = { transform ->
                    assertSame(admissionThread.get(), Thread.currentThread())
                    ui = ui.transform()
                },
                mainDispatcher = dispatcher,
            )

        fun export(removeLocal: Boolean = false) = owner.exportFile("space", "file", destination, removeLocal)

        suspend fun account(id: String) = onMain { ui = ui.forAccountLoad(accountContext.beginAccount(id)) }

        suspend fun assertPreparationCancelled() {
            val failure = runCatching { owner.prepareExternalFile(resource()) }.exceptionOrNull()
            assertTrue(failure is CancellationException)
        }

        suspend fun nextPreparation(): Preparation = withTimeout(5000) { preparations.receive() }

        suspend fun nextExport(): Export = withTimeout(5000) { exports.receive() }

        suspend fun <T> onMain(action: () -> T): T = withContext(dispatcher) { action() }

        override fun close() {
            scope.cancel()
            dispatcher.close()
        }
    }

    private class Preparation(
        val resource: ResourceEntity,
    ) {
        val result = CompletableDeferred<ResourceEntity>()
    }

    private class Export(
        val resource: ResourceEntity,
        val destination: Uri,
    ) {
        val result = CompletableDeferred<Unit>()
    }

    private companion object {
        fun resource() =
            ResourceEntity("a", "space", "file", null, "/file", "File", ResourceKind.FILE, null, 7, null, 0, 0)
    }
}
