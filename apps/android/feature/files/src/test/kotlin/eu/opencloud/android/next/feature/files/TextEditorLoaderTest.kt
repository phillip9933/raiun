package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.sync.TextDraftStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class TextEditorLoaderTest {
    @Test fun restoredFilePreservesDraftUntilExplicitDiscardThenLoadsCurrentContent() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val directory = resourceCacheDirectory(context.filesDir, "account", "space").apply { mkdirs() }
            val file = File(directory, "notes").apply { writeText("restored") }
            val current =
                ResourceEntity(
                    "account",
                    "space",
                    "file",
                    "root",
                    "/notes.txt",
                    "notes.txt",
                    ResourceKind.FILE,
                    "text/plain",
                    file.length(),
                    "\"restored\"",
                    0,
                    0,
                    hasLocalCopy = true,
                    localPath = file.path,
                )
            val drafts = TextDraftStore(context)
            val original = drafts.create(current.copy(eTag = "\"original\""), "unsaved edits".toByteArray())
            var refreshes = 0
            val staleListing = current.copy(eTag = "\"original\"")
            val loaded =
                loadTextEditorState(context, staleListing, drafts) {
                    refreshes++
                    current
                }
            assertEquals(1, refreshes)
            assertTrue(loaded.chooseDraft)
            assertTrue(loaded.serverChanged)
            assertEquals(original, loaded.draft)
            assertEquals(original, TextDraftStore(context).read("account", "space", "file"))
            assertEquals("restored", file.readText())
            drafts.discard(requireNotNull(loaded.draft))
            val fresh = loadTextEditorState(context, staleListing, drafts) { current }
            assertFalse(fresh.chooseDraft)
            assertEquals("restored", fresh.draft?.text)
            assertEquals("\"restored\"", fresh.draft?.baseETag)
        }
}
