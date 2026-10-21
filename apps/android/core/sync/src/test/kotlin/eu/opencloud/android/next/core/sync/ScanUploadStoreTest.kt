package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class ScanUploadStoreTest {
    @Test fun `scanner output must remain inside its owned directory`() {
        val store = ScanUploadStore(RuntimeEnvironment.getApplication()) { _, _, _, _ -> }
        val session = store.create("account", "space", "/Scans")
        val output = store.outputDirectory(session)
        val pdf = File(output, "scan.pdf").apply { writeText("pdf bytes") }
        assertThrows(IllegalArgumentException::class.java) {
            store.complete(session, listOf(File(output, "missing.pdf")), "application/pdf")
        }
        val elsewhere = File(RuntimeEnvironment.getApplication().cacheDir, "outside.jpg").apply { writeText("jpg") }
        assertThrows(IllegalArgumentException::class.java) { store.complete(session, listOf(elsewhere), "image/jpeg") }
        assertThrows(IllegalArgumentException::class.java) { store.complete(session, listOf(pdf), "") }
        assertFalse(store.hasCompletedOutput(session))
    }

    @Test fun `pdf outputs recover and enqueue with stable identities once`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val enqueued = mutableListOf<SharedUploadSource>()
            val store =
                ScanUploadStore(context) { account, space, parent, source ->
                    assertEquals(
                        listOf("account", "space", "/Scans"),
                        listOf(account, space, parent),
                    )
                    enqueued += source
                }
            val session = store.create("account", "space", "/Scans")
            val directory = store.outputDirectory(session)
            val pdf = File(directory, "scan.pdf").apply { writeText("pdf bytes") }
            store.complete(session, listOf(pdf), "application/pdf")
            assertTrue(ScanUploadStore(context) { _, _, _, _ -> }.hasCompletedOutput(session))

            store.submit(session)
            assertEquals(listOf("scan.pdf"), enqueued.map { it.name })
            assertTrue(enqueued.all { it.mimeType == "application/pdf" })
            assertTrue(enqueued.all { it.id.isNotBlank() })
            assertFalse(pdf.exists())

            ScanUploadStore(context) { _, _, _, source -> enqueued += source }.submit(session)
            assertEquals(1, enqueued.size)
        }

    @Test fun `jpeg mime type is carried into upload`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            var mime: String? = null
            val store = ScanUploadStore(context) { _, _, _, source -> mime = source.mimeType }
            val session = store.create("a", "s", "/")
            val jpg = File(store.outputDirectory(session), "scan.jpg").apply { writeText("jpeg") }
            store.complete(session, listOf(jpg), "image/jpeg")
            store.submit(session)
            assertEquals("image/jpeg", mime)
        }

    @Test fun `committed scanner directories recover after process death and pending directories are ignored`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val enqueued = mutableListOf<SharedUploadSource>()
            val initial = ScanUploadStore(context) { _, _, _, _ -> }
            val session = initial.create("a", "s", "/Scans")
            val output = initial.outputDirectory(session)
            val committed =
                File(output, "scan-63d18d8e-15ef-4bab-8b45-3a4a6ea94486/user.pdf")
                    .apply {
                        parentFile!!.mkdirs()
                        writeText("recovered pdf")
                    }
            File(output, ".pending-scan-ignored/user.pdf").apply {
                parentFile!!.mkdirs()
                writeText("partial")
            }

            val restored = ScanUploadStore(context) { _, _, _, source -> enqueued += source }
            assertTrue(restored.hasCompletedOutput(session))
            restored.submit(session)
            assertEquals(listOf("user.pdf"), enqueued.map { it.name })
            assertEquals("application/pdf", enqueued.single().mimeType)
            assertFalse(committed.exists())
            assertTrue(File(output, ".pending-scan-ignored/user.pdf").exists())
        }

    @Test fun `partial queue failure keeps outputs and retry reuses stable transfer ids`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val attempted = mutableListOf<String>()
            var fail = true
            val store =
                ScanUploadStore(context) { _, _, _, source ->
                    attempted += source.id
                    if (fail && source.name == "page-2.jpg") throw IOException("queue unavailable")
                }
            val session = store.create("a", "s", "/")
            val directory = store.outputDirectory(session)
            val first = File(directory, "page-1.jpg").apply { writeText("one") }
            val second = File(directory, "page-2.jpg").apply { writeText("two") }
            store.complete(session, listOf(first, second), "image/jpeg")
            assertThrows(IOException::class.java) { runBlocking { store.submit(session) } }
            assertTrue(first.exists())
            assertTrue(second.exists())
            val firstAttemptIds = attempted.toList()
            fail = false
            store.submit(session)
            assertEquals(firstAttemptIds, attempted.take(2))
            assertEquals(firstAttemptIds[0], attempted[2])
            assertEquals(firstAttemptIds[1], attempted[3])
            assertFalse(first.exists())
            assertFalse(second.exists())
        }

    @Test fun `account cleanup removes only that account scan sessions`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val store = ScanUploadStore(context) { _, _, _, _ -> }
            val own = store.create("account-a", "space", "/")
            val other = store.create("account-b", "space", "/")
            val ownDirectory = store.outputDirectory(own)
            val otherDirectory = store.outputDirectory(other)
            store.clearAccount("account-a")
            assertFalse(ownDirectory.exists())
            assertTrue(otherDirectory.exists())
        }

    @Test fun `cancellation preserves committed scan for retry`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val store = ScanUploadStore(context) { _, _, _, _ -> throw kotlinx.coroutines.CancellationException() }
            val session = store.create("account", "space", "/")
            val pdf = File(store.outputDirectory(session), "scan.pdf").apply { writeText("pdf bytes") }
            store.complete(session, listOf(pdf), "application/pdf")
            assertThrows(kotlinx.coroutines.CancellationException::class.java) { runBlocking { store.submit(session) } }
            assertTrue(pdf.exists())
            assertTrue(store.hasCompletedOutput(session))
        }

    @Test fun `corrupt completed manifest is reported rather than starting another scan`() {
        val store = ScanUploadStore(RuntimeEnvironment.getApplication()) { _, _, _, _ -> }
        val session = store.create("account", "space", "/")
        File(store.outputDirectory(session), "manifest.json").writeText("{}")
        assertThrows(org.json.JSONException::class.java) { store.hasCompletedOutput(session) }
    }

    @Test fun `scan defaults to launch folder and changed destination survives recreation`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val store = ScanUploadStore(context) { _, _, _, _ -> }
            val session = store.create("account", "team-space", "/Projects/Notes")
            assertEquals(ScanUploadLocation("account", "team-space", "/Projects/Notes"), store.location(session))
            store.changeLocation(session, "personal", "/")
            val reopened =
                ScanUploadStore(context) { account, space, path, _ ->
                    assertEquals(listOf("account", "personal", "/"), listOf(account, space, path))
                }
            assertEquals(ScanUploadLocation("account", "personal", "/"), reopened.location(session))
            val pdf = File(reopened.outputDirectory(session), "scan.pdf").apply { writeText("pdf bytes") }
            reopened.complete(session, listOf(pdf), "application/pdf")
            assertThrows(IllegalStateException::class.java) {
                runBlocking { reopened.changeLocation(session, "another-space", "/") }
            }
            reopened.submit(session)
        }
}
