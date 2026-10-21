package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class TextDraftStoreTest {
    private val draft =
        TextDraft(
            "account",
            "space",
            "resource",
            "/notes.txt",
            "notes.txt",
            "text/plain",
            "\"v1\"",
            "Line one\r\n日本語 🗂\n",
        )

    @Test fun `private drafts retain exact unicode and line endings across recreation`() {
        val context = RuntimeEnvironment.getApplication()
        TextDraftStore(context).save(draft)
        assertEquals(draft, TextDraftStore(context).read("account", "space", "resource"))
        assertNull(TextDraftStore(context).read("different account", "space", "resource"))
        assertThrows(IllegalArgumentException::class.java) {
            TextDraftStore(context).save(draft.copy(text = "x".repeat(TextDraftStore.MAX_TEXT_BYTES + 1)))
        }
        assertEquals(draft, TextDraftStore(context).read("account", "space", "resource"))
    }

    @Test fun `interrupted submission reuses durable identity and original version`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val ids = mutableListOf<String>()
            val first = TextDraftStore(context)
            try {
                first.submit(draft) { source ->
                    ids += source.id
                    assertEquals(draft.text, source.payload.readText())
                    throw IOException("interruption after accepting intent")
                }
            } catch (_: IOException) {
                // Simulate caller retaining the pre-submit value across a lost completion response.
            }
            val queued =
                TextDraftStore(context).submit(draft) { source ->
                    ids += source.id
                    assertEquals(draft.baseETag, source.expectedETag)
                    assertEquals(draft.resourceId, source.resourceId)
                }
            assertEquals(2, ids.size)
            assertEquals(ids.first(), ids.last())
            assertEquals(ids.first(), queued.queuedId)
        }

    @Test fun `only verified saves rebase drafts and keep both cannot rebase the original`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database =
                androidx.room.Room
                    .inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java)
                    .build()
            val store = FileBrowserStore(database)
            database.accountDao().upsert(
                eu.opencloud.android.next.core.database.AccountEntity(
                    "account",
                    "https://example.test",
                    "user",
                    "User",
                    "BASIC",
                    false,
                ),
            )
            database.spaceDao().insert(
                eu.opencloud.android.next.core.database.SpaceEntity(
                    "account",
                    "space",
                    "Space",
                    "project",
                    null,
                    null,
                    "root",
                    "https://example.test/dav",
                    null,
                    null,
                ),
            )
            val drafts = TextDraftStore(context, store)
            val queued = draft.copy(queuedId = "save")
            val transfer =
                TransferEntity(
                    "save",
                    "account",
                    "space",
                    "resource",
                    "UPLOAD",
                    "file:///private/staged",
                    "/notes.txt",
                    "notes.txt",
                    "text/plain",
                    12,
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                    state = "FAILED",
                    expectedETag = draft.baseETag,
                )
            store.enqueueTransfer(transfer)
            assertEquals(queued, drafts.resume(queued))
            store.updateTransfer(transfer.copy(state = "SUCCEEDED", verifiedETag = "\"v2\""))
            assertEquals(draft.copy(baseETag = "\"v2\""), drafts.resume(queued))
            store.updateTransfer(
                transfer.copy(state = "SUCCEEDED", destinationPath = "/notes (1).txt", verifiedETag = "\"copy\""),
            )
            assertEquals(draft, drafts.resume(queued))
            database.close()
        }
}
