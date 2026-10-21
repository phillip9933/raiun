package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class DocumentEditStoreTest {
    private val context = RuntimeEnvironment.getApplication()
    private val resource =
        ResourceEntity(
            "account",
            "space",
            "resource",
            null,
            "/note.txt",
            "note.txt",
            ResourceKind.FILE,
            "text/plain",
            5,
            "\"v1\"",
            0,
            0,
        )

    private fun original() = File(context.cacheDir, "original.txt").apply { writeText("hello") }

    @Test fun `files without a strong server version cannot start an edit`() =
        runTest {
            val store = DocumentEditStore(context)
            for (etag in listOf(null, "W/\"v1\"", "")) {
                try {
                    store.begin(resource.copy(eTag = etag), original())
                    org.junit.Assert.fail("Unversioned edit was accepted")
                } catch (_: IllegalArgumentException) {
                    assertTrue(store.pending(resource.accountId).isEmpty())
                }
            }
        }

    @Test fun `intentional empty edits remain valid after clean closure`() =
        runTest {
            val store = DocumentEditStore(context)
            val opened = store.begin(resource, original())
            store.workingFile(opened).writeBytes(byteArrayOf())
            val ready = store.finish(opened, cleanClose = true, authorized = true)
            assertEquals(0L, ready.sealedSize)
            store.submit(ready) { _, source ->
                assertEquals(0L, source.payload.length())
                assertEquals("\"v1\"", source.expectedETag)
            }
        }

    @Test fun `unclosed draft survives recreation and cannot be automatically submitted`() =
        runTest {
            val first = DocumentEditStore(context)
            val source = original()
            val edit = first.begin(resource, source)
            first.workingFile(edit).writeText("partial")
            val recovered = DocumentEditStore(context)
            assertEquals(edit, recovered.pending(resource.accountId).single())
            assertEquals("partial", recovered.workingFile(edit).readText())
            assertEquals("hello", source.readText())
            try {
                recovered.submit(edit) { _, _ -> org.junit.Assert.fail("Unclosed edits must not upload") }
                org.junit.Assert.fail("Unclosed edit was accepted")
            } catch (_: IllegalStateException) {
                assertEquals(DocumentEditState.OPEN, recovered.pending(resource.accountId).single().state)
            }
        }

    @Test fun `failed closure and revoked authorization retain drafts for review`() =
        runTest {
            for ((clean, authorized) in listOf(false to true, true to false)) {
                val item = resource.copy(remoteId = "$clean-$authorized")
                val store = DocumentEditStore(context)
                val opened = store.begin(item, original())
                val working = store.workingFile(opened)
                working.writeText("edited")
                val review = store.finish(opened, clean, authorized)
                assertEquals(DocumentEditState.REVIEW, review.state)
                assertEquals("edited", working.readText())
                try {
                    store.submit(review) { _, _ -> org.junit.Assert.fail("Unapproved edits must not upload") }
                    org.junit.Assert.fail("Review draft was accepted")
                } catch (_: IllegalStateException) {
                    assertTrue(store.pending(item.accountId).any { it == review })
                }
            }
        }

    @Test fun `clean closure seals independent bytes and keeps original server version`() =
        runTest {
            val store = DocumentEditStore(context)
            val opened = store.begin(resource, original())
            val working = store.workingFile(opened)
            working.writeText("世界\n")
            val ready = store.finish(opened, cleanClose = true, authorized = true)
            working.writeText("late write")
            val submitted =
                store.submit(ready) { saved, source ->
                    assertEquals("世界\n", source.payload.readText())
                    assertEquals("\"v1\"", source.expectedETag)
                    assertEquals(resource.remoteId, source.resourceId)
                    assertEquals(ready.id, source.id)
                    assertEquals(ready, saved)
                }
            assertEquals(DocumentEditState.SUBMITTED, submitted.state)
            assertEquals(submitted, store.submit(ready) { _, _ -> error("Duplicate submission") })
        }

    @Test fun `lost enqueue acknowledgment reuses stable identity across process recreation`() =
        runTest {
            val store = DocumentEditStore(context)
            val opened = store.begin(resource, original())
            val ready = store.finish(opened, cleanClose = true, authorized = true)
            val ids = mutableListOf<String>()
            try {
                store.submit(ready) { _, source ->
                    ids += source.id
                    throw IOException("Lost acknowledgment")
                }
            } catch (_: IOException) {
                assertEquals(DocumentEditState.READY, store.pending(resource.accountId).single().state)
            }
            DocumentEditStore(context).submit(ready) { _, source -> ids += source.id }
            assertEquals(listOf(ready.id, ready.id), ids)
        }

    @Test fun `cancellation stays cancellation and preserves the sealed pending edit`() =
        runTest {
            val store = DocumentEditStore(context)
            val ready = store.finish(store.begin(resource, original()), cleanClose = true, authorized = true)
            val cancelled = CancellationException("cancelled")
            try {
                store.submit(ready) { _, _ -> throw cancelled }
                org.junit.Assert.fail("Cancellation was swallowed")
            } catch (failure: CancellationException) {
                assertTrue(failure === cancelled)
                assertEquals(ready, store.pending(resource.accountId).single())
            }
        }

    @Test fun `modified sealed bytes are rejected and another account cannot see the edit`() =
        runTest {
            val store = DocumentEditStore(context)
            val opened = store.begin(resource, original())
            val working = store.workingFile(opened)
            val ready = store.finish(opened, cleanClose = true, authorized = true)
            File(working.parentFile, "sealed").writeText("other")
            assertTrue(store.pending("different account").isEmpty())
            try {
                store.submit(ready) { _, _ -> org.junit.Assert.fail("Modified sealed payload must not upload") }
                org.junit.Assert.fail("Changed sealed content was accepted")
            } catch (_: IllegalStateException) {
                assertFalse(store.pending(resource.accountId).isEmpty())
            }
        }

    @Test fun `an existing draft cannot be overwritten by another editing session`() =
        runTest {
            val store = DocumentEditStore(context)
            val first = store.begin(resource, original())
            try {
                DocumentEditStore(context).begin(resource, original())
                org.junit.Assert.fail("Existing draft was replaced")
            } catch (_: IllegalStateException) {
                assertEquals(first, store.pending(resource.accountId).single())
            }
        }
}
