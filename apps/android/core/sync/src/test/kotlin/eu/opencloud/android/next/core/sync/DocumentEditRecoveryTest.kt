package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.cacheIdentity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream
import java.io.File

@RunWith(RobolectricTestRunner::class)
class DocumentEditRecoveryTest {
    private val context = RuntimeEnvironment.getApplication()
    private val drafts = DocumentEditStore(context)
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
    private val source get() = File(context.cacheDir, "original").apply { writeText("hello") }

    @Test fun `account cleanup waits for upload staging and removes its late files`() =
        runBlocking {
            val ready = drafts.finish(drafts.begin(resource, source), cleanClose = true, authorized = true)
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val staged = File(context.noBackupFilesDir, "upload-sources/${cacheIdentity("account")}/late/payload")
            val submit =
                async {
                    drafts.submit(ready) { _, _ ->
                        entered.complete(Unit)
                        release.await()
                        staged.parentFile!!.mkdirs()
                        staged.writeText("edited")
                    }
                }
            entered.await()
            val cleanup = async { clearAccountPrivateFiles(context, "account") }
            yield()
            assertFalse(cleanup.isCompleted)
            release.complete(Unit)
            submit.await()
            cleanup.await()
            assertFalse(staged.exists())
            assertTrue(drafts.pending("account").isEmpty())
        }

    @Test fun `authorization is checked under the journal lock before creating a draft`() =
        runBlocking {
            assertThrows(IllegalStateException::class.java) {
                runBlocking { drafts.begin(resource, source, authorized = { false }) }
            }
            assertTrue(drafts.pending("account").isEmpty())
        }

    @Test fun `one corrupt journal does not hide other drafts or remove damaged files`() =
        runBlocking {
            val edit = drafts.begin(resource, source)
            val damaged = File(context.noBackupFilesDir, "document-edits/${cacheIdentity("account")}/bad/bad/edit.json")
            damaged.parentFile!!.mkdirs()
            damaged.writeText("broken json")
            val inventory = drafts.inventory("account")
            assertEquals(listOf(edit), inventory.edits)
            assertEquals(1, inventory.unreadableCount)
            assertEquals("broken json", damaged.readText())
        }

    @Test fun `revoked export access stops copying and preserves the draft`() =
        runBlocking {
            val edit = drafts.begin(resource, source)
            val output = ByteArrayOutputStream()
            var checks = 0
            assertThrows(IllegalStateException::class.java) {
                runBlocking { drafts.export(edit, output) { check(++checks < 2) } }
            }
            assertEquals(0, output.size())
            assertEquals(edit, drafts.pending("account").single())
        }

    @Test fun `active editors cannot be exported or discarded by recovery controls`() =
        runBlocking {
            val edit = drafts.begin(resource, source, reserveWriter = true)
            assertThrows(
                IllegalStateException::class.java,
            ) { runBlocking { drafts.export(edit, ByteArrayOutputStream()) } }
            assertThrows(IllegalStateException::class.java) { runBlocking { drafts.discard(edit) } }
            val review = drafts.requireReview(edit)!!
            val output = ByteArrayOutputStream()
            drafts.export(review, output)
            assertEquals("hello", output.toString("UTF-8"))
            drafts.discard(review)
            assertTrue(drafts.pending("account").isEmpty())
        }

    @Test fun `exporting and discarding a failed edit preserves the original downloaded bytes`() =
        runBlocking {
            val original = source
            val edit = drafts.begin(resource, original)
            drafts.workingFile(edit).writeText("partial edits")
            val review = drafts.finish(edit, cleanClose = false, authorized = true)
            val recovered = ByteArrayOutputStream()
            DocumentEditStore(context).export(review, recovered)
            assertEquals("partial edits", recovered.toString("UTF-8"))
            drafts.discard(review)
            assertEquals("hello", original.readText())
        }

    @Test fun `stale recovery actions cannot discard a newer edit of the same file`() =
        runBlocking {
            val first = drafts.begin(resource, source)
            drafts.discard(first)
            val second = drafts.begin(resource, source)
            assertThrows(IllegalStateException::class.java) { runBlocking { drafts.discard(first) } }
            assertEquals(null, drafts.requireReview(first))
            assertEquals(second, drafts.pending("account").single())
        }

    @Test fun `sealed pending saves cannot be discarded and export uses their verified sealed bytes`() =
        runBlocking<Unit> {
            val edit = drafts.begin(resource, source)
            val working = drafts.workingFile(edit)
            val ready = drafts.finish(edit, cleanClose = true, authorized = true)
            working.writeText("late edit")
            val output = ByteArrayOutputStream()
            drafts.export(ready, output)
            assertEquals("hello", output.toString("UTF-8"))
            assertThrows(IllegalStateException::class.java) { runBlocking { drafts.discard(ready) } }
        }
}
