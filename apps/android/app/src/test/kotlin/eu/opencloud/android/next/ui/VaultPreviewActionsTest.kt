package eu.opencloud.android.next.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.work.Configuration
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.sync.VaultExternalCopyLease
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultPreviewActionsTest {
    @Before fun initializeWorkManager() {
        WorkManagerTestInitHelper.initializeTestWorkManager(
            ApplicationProvider.getApplicationContext<Application>(),
            Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
        )
    }

    @After fun closeWorkManager() {
        WorkManagerTestInitHelper.closeWorkDatabase()
        VaultExternalCopyStore.initializeProcess(ApplicationProvider.getApplicationContext<Application>())
    }

    @Test fun `cancellation before save starts wipes the owned edit without queuing a replacement`() =
        runTest {
            val fixture = fixture()
            val preview = fixture.loadPreview()
            val bytes = "edited".toByteArray()

            fixture.actions.saveText(preview, bytes)
            fixture.owner.nextGeneration()
            advanceUntilIdle()

            assertTrue(bytes.all { it == 0.toByte() })
            assertEquals(0, fixture.session.replacements)
            assertEquals(0, fixture.owner.reloads)
            assertFalse(fixture.session.closed)
            fixture.content.clear()
        }

    @Test fun `late uncertain save cannot forget a replacement preview or make it read only`() =
        runTest {
            var pending: Continuation<Unit>? = null
            val fixture = fixture()
            fixture.session.queue = { suspendCoroutine { pending = it } }
            val original = fixture.loadPreview()
            val edit = "old edit".toByteArray()
            fixture.actions.saveText(original, edit)
            runCurrent()
            assertTrue(pending != null)

            fixture.owner.nextGeneration()
            fixture.content.clear()
            val replacement = fixture.loadPreview("replacement.txt")
            val replacementRequest = fixture.content.loadedRequest
            requireNotNull(pending).resumeWithException(IOException("Synthetic uncertain admission"))
            advanceUntilIdle()

            assertTrue(edit.all { it == 0.toByte() })
            assertSame(replacement, fixture.state.value.preview)
            assertSame(replacementRequest, fixture.content.loadedRequest)
            assertTrue(replacement.editable)
            assertEquals("replacement.txt", String(replacement.bytes))
            assertFalse(fixture.state.value.previewSaving)
            assertNull(fixture.state.value.previewSaveError)
            assertEquals(0, fixture.owner.reloads)
            assertTrue(fixture.owner.failures.isEmpty())
            fixture.content.clear()
        }

    @Test fun `late accepted save cannot close a replacement preview or publish old queue feedback`() =
        runTest {
            var pending: Continuation<Unit>? = null
            val fixture = fixture()
            fixture.session.queue = { suspendCoroutine { pending = it } }
            val original = fixture.loadPreview()
            val edit = "accepted old edit".toByteArray()
            fixture.actions.saveText(original, edit)
            runCurrent()
            assertTrue(pending != null)

            fixture.owner.nextGeneration()
            fixture.content.clear()
            val replacement = fixture.loadPreview("new.txt")
            val replacementRequest = fixture.content.loadedRequest
            requireNotNull(pending).resume(Unit)
            advanceUntilIdle()

            assertEquals(1, fixture.session.replacements)
            assertTrue(edit.all { it == 0.toByte() })
            assertSame(replacement, fixture.state.value.preview)
            assertSame(replacementRequest, fixture.content.loadedRequest)
            assertEquals("new.txt", String(replacement.bytes))
            assertEquals(0L, fixture.state.value.queuedUploadCount)
            assertEquals(0, fixture.owner.reloads)
            assertFalse(fixture.session.closed)
            fixture.content.clear()
        }

    @Test fun `invalid edit range wipes bytes without consuming the preview version`() =
        runTest {
            val fixture = fixture()
            val preview = fixture.loadPreview()
            val request = fixture.content.loadedRequest
            val bytes = "invalid range".toByteArray()

            fixture.actions.saveText(preview, bytes, offset = -1, length = 1)

            assertTrue(bytes.all { it == 0.toByte() })
            assertEquals(0L, fixture.owner.token)
            assertSame(request, fixture.content.loadedRequest)
            assertSame(preview, fixture.state.value.preview)
            assertEquals(0, fixture.session.replacements)
            fixture.content.clear()
        }

    @Test fun `external launch failure revokes the produced plaintext lease`() =
        runTest {
            val fixture = fixture()
            assertTrue(VaultExternalCopyStore.initializeProcess(fixture.application, scheduleRetry = false))
            var handed: VaultExternalCopyLease? = null
            val launched = CompletableDeferred<Unit>()
            fixture.actions.openWith(fixture.handoff()) { lease ->
                handed = lease
                launched.complete(Unit)
                throw IOException("Synthetic launcher failure")
            }
            runCurrent()
            awaitIo(launched)
            advanceUntilIdle()

            val lease = requireNotNull(handed)
            assertNull(VaultExternalCopyStore.find(fixture.application, lease.uri))
            assertTrue(fixture.exportRoot.listFiles().isNullOrEmpty())
            assertEquals(listOf(VaultRouteError.PREVIEW), fixture.owner.failures)
            assertFalse(fixture.state.value.loading)
            assertFalse(fixture.session.closed)
        }

    @Test fun `successful external launch transfers lease cleanup to the caller`() =
        runTest {
            val fixture = fixture()
            assertTrue(VaultExternalCopyStore.initializeProcess(fixture.application, scheduleRetry = false))
            var handed: VaultExternalCopyLease? = null
            val launched = CompletableDeferred<Unit>()
            fixture.actions.openWith(fixture.handoff()) { lease ->
                handed = lease
                launched.complete(Unit)
            }
            runCurrent()
            awaitIo(launched)
            advanceUntilIdle()

            val lease = requireNotNull(handed)
            try {
                assertEquals(
                    "plaintext",
                    VaultExternalCopyStore.openReadOnly(fixture.application, lease.uri)?.readText(),
                )
                assertTrue(fixture.owner.failures.isEmpty())
                assertFalse(fixture.state.value.loading)
            } finally {
                lease.cleanup()
            }
            assertTrue(fixture.exportRoot.listFiles().isNullOrEmpty())
        }

    @Test fun `route closure cleans a late plaintext export even when download ignores cancellation`() =
        runTest {
            val fixture = fixture()
            assertTrue(VaultExternalCopyStore.initializeProcess(fixture.application, scheduleRetry = false))
            val pending = CompletableDeferred<Continuation<Unit>>()
            val finished = CompletableDeferred<Unit>()
            fixture.session.download = { sink ->
                sink.write("late plaintext".toByteArray())
                // A provider/network boundary may return despite operation cancellation.
                suspendCoroutine { pending.complete(it) }
                finished.complete(Unit)
            }
            var launches = 0
            fixture.actions.openWith(fixture.handoff()) { launches++ }
            runCurrent()
            val continuation = awaitIo(pending)
            assertTrue(fixture.exportRoot.walkTopDown().any { it.isFile && it.length() > 0 })

            fixture.owner.active = false
            fixture.owner.nextGeneration()
            val replacementState = VaultRouteState(mode = VaultRouteMode.CATALOG)
            fixture.state.value = replacementState
            continuation.resume(Unit)
            awaitIo(finished)
            // The IO producer must unwind before its discarded lease can be checked.
            withContext(Dispatchers.Default) {
                withTimeout(5_000) { requireNotNull(fixture.owner.job).join() }
            }
            advanceUntilIdle()

            assertEquals(0, launches)
            assertSame(replacementState, fixture.state.value)
            assertTrue(fixture.exportRoot.listFiles().isNullOrEmpty())
            assertTrue(fixture.owner.failures.isEmpty())
            assertFalse(fixture.session.closed)
        }

    private suspend fun <T> awaitIo(ready: CompletableDeferred<T>): T =
        withContext(Dispatchers.Default) { withTimeout(5_000) { ready.await() } }

    private fun TestScope.fixture(): Fixture {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val session = Session()
        val owner = Owner(session)
        val state = MutableStateFlow(VaultRouteState(mode = VaultRouteMode.CONTENTS))
        val dispatcher = StandardTestDispatcher(testScheduler)
        val content =
            VaultPreviewContent(
                application,
                dispatcher,
                state,
                object : VaultPreviewOwner {
                    override fun isCurrent(request: VaultPreviewRequest): Boolean =
                        owner.isCurrent(request.session, request.token, request.account)

                    override fun backingAccessValid(request: VaultPreviewRequest): Boolean = owner.active

                    override fun isThumbnailCurrent(request: VaultThumbnailRequest): Boolean = false

                    override fun reportFailure(
                        request: VaultPreviewRequest,
                        failure: Exception,
                    ) = error("No preview failure expected.")
                },
            )
        return Fixture(
            application,
            session,
            owner,
            state,
            content,
            VaultPreviewActions(application, dispatcher, this, state, content, owner),
        )
    }

    private class Fixture(
        val application: Application,
        val session: Session,
        val owner: Owner,
        val state: MutableStateFlow<VaultRouteState>,
        val content: VaultPreviewContent,
        val actions: VaultPreviewActions,
    ) {
        val exportRoot get() = File(application.noBackupFilesDir, "vault-external-copies")

        suspend fun loadPreview(name: String = "notes.txt"): VaultRoutePreview {
            val entry = VaultViewModelRaceTest().folder(name).copy(strongETag = "\"original\"")
            content.load(
                VaultPreviewRequest(
                    session,
                    "account",
                    entry,
                    name,
                    VaultPreviewKind.TEXT,
                    Long.MAX_VALUE,
                    owner.token,
                ),
            )
            return requireNotNull(state.value.preview)
        }

        fun handoff() =
            VaultExternalHandoffRequest(session, "account", VaultViewModelRaceTest().folder("notes.txt"), owner.token)
    }

    private class Owner(
        private val opened: VaultRouteSession,
    ) : VaultPreviewActionOwner {
        var token = 0L
        var active = true
        var job: Job? = null
        var reloads = 0
        val failures = mutableListOf<VaultRouteError>()

        override fun isCurrent(
            opened: VaultRouteSession,
            token: Long,
            account: String,
        ): Boolean = active && opened === this.opened && token == this.token && account == "account"

        override fun nextGeneration(): Long {
            token++
            job?.cancel()
            return token
        }

        override fun trackOperation(job: Job) {
            this.job = job
        }

        override suspend fun revalidateSource(
            opened: VaultRouteSession,
            expected: VaultFolder,
        ): VaultFolder = expected

        override fun reloadContents(
            opened: VaultRouteSession,
            token: Long,
            account: String,
        ) {
            reloads++
        }

        override fun reportFailure(
            failure: Exception,
            fallback: VaultRouteError,
            context: VaultFailureContext,
        ) {
            failures += fallback
        }
    }

    private class Session : VaultRouteSession {
        override val identity = VaultViewModelRaceTest.identity
        var replacements = 0
        var closed = false
        var queue: suspend () -> Unit = {}
        var download: suspend (OutputStream) -> Unit = { it.write("plaintext".toByteArray()) }

        override suspend fun queueReplacement(
            entry: VaultFolder,
            source: InputStream,
            size: Long,
        ) {
            queue()
            replacements++
        }

        override suspend fun list(path: String): List<VaultFolder> = emptyList()

        override suspend fun preview(entry: VaultFolder): ByteArray = entry.name.toByteArray()

        override suspend fun exportVerifiedKeyMaterial(): ByteArray = error("No key export expected.")

        override suspend fun download(
            entry: VaultFolder,
            sink: OutputStream,
            maxPlaintextBytes: Long,
        ): Long {
            download(sink)
            return 0
        }

        override fun close() {
            closed = true
        }
    }
}
