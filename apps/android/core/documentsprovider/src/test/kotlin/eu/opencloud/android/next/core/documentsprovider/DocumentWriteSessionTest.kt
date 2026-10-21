package eu.opencloud.android.next.core.documentsprovider

import android.os.CancellationSignal
import android.os.OperationCanceledException
import android.os.ParcelFileDescriptor
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.DocumentEditState
import eu.opencloud.android.next.core.sync.DocumentEditStore
import eu.opencloud.android.next.core.sync.clearAccountPrivateFiles
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class DocumentWriteSessionTest {
    private val context = RuntimeEnvironment.getApplication()
    private val drafts = DocumentEditStore(context)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val resource =
        ResourceEntity(
            "account",
            "space",
            "resource",
            null,
            "/file",
            "file",
            ResourceKind.FILE,
            "text/plain",
            5,
            "\"v1\"",
            0,
            0,
        )
    private val original get() = File(context.cacheDir, "source").apply { writeText("hello") }
    private var allowed = true
    private var submitted = 0
    private lateinit var closed: (IOException?) -> Unit
    private lateinit var working: File
    private val session =
        DocumentWriteSession(drafts, scope, { allowed }, {
            submitted++
        }) { file, mode, callback ->
            working = file
            closed = callback
            ParcelFileDescriptor.open(file, mode)
        }

    @After fun tearDown() = scope.cancel()

    @Test fun `seekable edits seal once after clean closure without modifying the original cache`() =
        runBlocking {
            val source = original
            val descriptor = session.open(resource, source, "rw", null)
            ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use {
                it.channel.position(1)
                it.write("XYZ".toByteArray())
            }
            closed(null)
            closed(null)
            awaitCompletion()
            assertEquals("hXYZo", working.readText())
            assertEquals("hello", source.readText())
            assertEquals(1, submitted)
            assertEquals(DocumentEditState.READY, drafts.pending("account").single().state)
        }

    @Test fun `truncating and append modes preserve their expected file semantics`() =
        runBlocking {
            for ((mode, initial) in listOf("rw" to "hello", "wa" to "hello", "w" to "", "wt" to "", "rwt" to "")) {
                val item = resource.copy(remoteId = mode)
                val descriptor = session.open(item, original, mode, null)
                assertEquals(initial, working.readText())
                ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { it.write('!'.code) }
                assertEquals(
                    if (mode == "wa") {
                        "hello!"
                    } else if (mode == "rw") {
                        "!ello"
                    } else {
                        "!"
                    },
                    working.readText(),
                )
                closed(IOException("editor failed"))
                awaitCompletion()
            }
            assertEquals(0, submitted)
            assertTrue(drafts.pending("account").all { it.state == DocumentEditState.REVIEW })
        }

    @Test fun `revoked authorization prevents upload after a successful editor close`() =
        runBlocking {
            val descriptor = session.open(resource, original, "rw", null)
            allowed = false
            descriptor.close()
            closed(null)
            awaitCompletion()
            assertEquals(0, submitted)
            assertEquals(DocumentEditState.REVIEW, drafts.pending("account").single().state)
        }

    @Test fun `cancelled or failed editing remains a review draft`() =
        runBlocking {
            val signal = CancellationSignal()
            val descriptor = session.open(resource, original, "rw", signal)
            signal.cancel()
            descriptor.close()
            closed(null)
            awaitCompletion()
            assertEquals(0, submitted)
            assertEquals(DocumentEditState.REVIEW, drafts.pending("account").single().state)
        }

    @Test fun `cancelled open and invalid modes do not create journals`() =
        runBlocking {
            val cancelled = CancellationSignal().apply { cancel() }
            assertThrows(OperationCanceledException::class.java) {
                runBlocking { session.open(resource, original, "rw", cancelled) }
            }
            assertThrows(UnsupportedOperationException::class.java) {
                runBlocking { session.open(resource, original, "invalid", null) }
            }
            assertTrue(drafts.pending("account").isEmpty())
        }

    @Test fun `failed descriptor creation releases its writer and retains recoverable data`() =
        runBlocking {
            val failing =
                DocumentWriteSession(drafts, scope, { true }, {}) { _, _, _ -> throw IOException("open failed") }
            assertThrows(IOException::class.java) {
                runBlocking { failing.open(resource, original, "rw", null) }
            }
            val saved = drafts.pending("account").single()
            assertEquals(DocumentEditState.REVIEW, saved.state)
            assertEquals(false, drafts.writerActive(saved))
        }

    @Test fun `a close after account removal cannot resurrect the private draft`() =
        runBlocking {
            val descriptor = session.open(resource, original, "rw", null)
            val edit = drafts.pending("account").single()
            descriptor.close()
            clearAccountPrivateFiles(context, "account")
            closed(null)
            awaitCompletion()
            assertTrue(drafts.pending("account").isEmpty())
            assertEquals(false, drafts.writerActive(edit))
            assertEquals(0, submitted)
        }

    private suspend fun awaitCompletion() {
        withTimeout(5000) {
            scope.coroutineContext[Job]!!
                .children
                .toList()
                .forEach { it.join() }
        }
    }

    @Test fun `cleanup failure cannot replace cancellation during descriptor creation`() =
        runBlocking {
            val cancelled = kotlinx.coroutines.CancellationException("original cancellation")
            val failing =
                DocumentWriteSession(drafts, scope, { true }, {}) { file, _, _ ->
                    File(file.parentFile, "edit.json").writeText("{")
                    throw cancelled
                }
            try {
                failing.open(resource, original, "rw", null)
                org.junit.Assert.fail("Cancellation was swallowed")
            } catch (failure: kotlinx.coroutines.CancellationException) {
                assertTrue(failure === cancelled)
                assertEquals(1, failure.suppressed.size)
            }
        }
}
