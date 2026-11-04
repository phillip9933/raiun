package eu.opencloud.android.next.ui

import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.OutputStream
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultPreviewContentTest {
    @Test fun `late streamed preview closes only its own backing and leaves replacement readable`() =
        runTest {
            var pendingDownload: Continuation<Unit>? = null
            val opened =
                Session(download = { entry, sink ->
                    sink.write(entry.name.toByteArray())
                    if (entry.name == "old.txt") suspendCoroutine { pendingDownload = it }
                })
            val owner = Owner(opened)
            val state = MutableStateFlow(VaultRouteState(loading = true))
            val application = ApplicationProvider.getApplicationContext<android.app.Application>()
            val content = VaultPreviewContent(application, StandardTestDispatcher(testScheduler), state, owner)
            val old = request(opened, "old.txt", token = 0, size = 9L * 1024 * 1024)
            val current = request(opened, "new.txt", token = 1, size = 9L * 1024 * 1024)
            val first = launch { content.load(old) }
            runCurrent()
            assertTrue(pendingDownload != null)
            val oldFile = requireNotNull(java.io.File(application.cacheDir, "encrypted-previews").listFiles()).single()

            owner.token = 1
            content.load(current)
            val published = requireNotNull(state.value.preview)
            val backing = requireNotNull(published.backing)
            requireNotNull(pendingDownload).resume(Unit)
            advanceUntilIdle()
            first.join()

            assertFalse(oldFile.exists())
            assertSame(published, state.value.preview)
            assertSame(current, content.loadedRequest)
            assertEquals("new.txt", backing.inputStream().use { String(it.readBytes()) })
            assertTrue(owner.failures.isEmpty())
            content.clear()
            assertTrue(runCatching { backing.size }.isFailure)
            assertNull(content.loadedRequest)
            assertFalse(opened.closed)
        }

    @Test fun `late thumbnail is wiped while the serialized replacement retains its bytes`() =
        runTest {
            var pendingPreview: Continuation<ByteArray>? = null
            var calls = 0
            val currentBytes = "new thumbnail".toByteArray()
            val opened =
                Session(preview = {
                    calls++
                    if (calls == 1) suspendCoroutine { pendingPreview = it } else currentBytes
                })
            val owner = Owner(opened)
            val state = MutableStateFlow(VaultRouteState())
            val content =
                VaultPreviewContent(
                    ApplicationProvider.getApplicationContext(),
                    StandardTestDispatcher(testScheduler),
                    state,
                    owner,
                )
            val old = thumbnail(opened, 0)
            val current = thumbnail(opened, 1)
            val first = async { content.loadThumbnail(old) }
            runCurrent()
            val second = async { content.loadThumbnail(current) }
            runCurrent()
            assertEquals(1, calls)

            owner.token = 1
            val lateBytes = "old thumbnail".toByteArray()
            requireNotNull(pendingPreview).resume(lateBytes)
            advanceUntilIdle()

            assertNull(first.await())
            assertTrue(lateBytes.all { it == 0.toByte() })
            assertSame(currentBytes, second.await())
            assertEquals("new thumbnail", String(currentBytes))
            assertEquals(2, calls)
            currentBytes.fill(0)
            assertFalse(opened.closed)
        }

    @Test fun `clearing a published memory preview wipes its buffer and drops the saved source`() =
        runTest {
            val bytes = "private text".toByteArray()
            val opened = Session(preview = { bytes })
            val owner = Owner(opened)
            val state = MutableStateFlow(VaultRouteState(loading = true))
            val content =
                VaultPreviewContent(
                    ApplicationProvider.getApplicationContext(),
                    StandardTestDispatcher(testScheduler),
                    state,
                    owner,
                )
            val request = request(opened, "notes.txt", token = 0, size = bytes.size.toLong())
            content.load(request)
            assertSame(bytes, state.value.preview?.bytes)
            assertSame(request, content.loadedRequest)

            content.clear()

            assertTrue(bytes.all { it == 0.toByte() })
            assertNull(content.loadedRequest)
            assertFalse(state.value.previewSaving)
            assertNull(state.value.previewSaveError)
            assertFalse(opened.closed)
        }

    private fun request(
        session: VaultRouteSession,
        name: String,
        token: Long,
        size: Long,
    ) = VaultPreviewRequest(
        session,
        "account",
        VaultViewModelRaceTest().folder(name).copy(size = size),
        name,
        VaultPreviewKind.TEXT,
        Long.MAX_VALUE,
        token,
    )

    private fun thumbnail(
        session: VaultRouteSession,
        token: Long,
    ): VaultThumbnailRequest {
        val file = VaultViewModelRaceTest().folder("image.png")
        val route = VaultRouteEntry(file.id, file.name, file.path, false, false, file.size, file.contentType)
        return VaultThumbnailRequest(session, "account", token, PresentedVaultFolder(route, file))
    }

    private class Owner(
        private val session: VaultRouteSession,
    ) : VaultPreviewOwner {
        var token = 0L
        val failures = mutableListOf<Exception>()

        override fun isCurrent(request: VaultPreviewRequest): Boolean =
            request.token == token && request.session === session

        // A route generation change does not revoke an already displayed backing from the same session.
        override fun backingAccessValid(request: VaultPreviewRequest): Boolean = request.session === session

        override fun isThumbnailCurrent(request: VaultThumbnailRequest): Boolean =
            request.token == token && request.session === session

        override fun reportFailure(
            request: VaultPreviewRequest,
            failure: Exception,
        ) {
            if (isCurrent(request)) failures += failure
        }
    }

    private class Session(
        private val preview: suspend (VaultFolder) -> ByteArray = { error("No memory preview expected.") },
        private val download: suspend (VaultFolder, OutputStream) -> Unit = { _, _ -> error("No download expected.") },
    ) : VaultRouteSession {
        override val identity = VaultViewModelRaceTest.identity
        var closed = false

        override suspend fun list(path: String): List<VaultFolder> = emptyList()

        override suspend fun preview(entry: VaultFolder): ByteArray = preview.invoke(entry)

        override suspend fun exportVerifiedKeyMaterial(): ByteArray = error("No key export expected.")

        override suspend fun download(
            entry: VaultFolder,
            sink: OutputStream,
            maxPlaintextBytes: Long,
        ): Long {
            download.invoke(entry, sink)
            return 0L
        }

        override fun close() {
            closed = true
        }
    }
}
