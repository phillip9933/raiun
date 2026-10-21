package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class DocumentEditReconcilerTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = FileBrowserStore(database)
    private val drafts = DocumentEditStore(context)
    private val reconciler = DocumentEditReconciler(context, store)
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

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(
                AccountEntity("account", "https://example.test", "user", "User", "BASIC", false),
            )
        }

    @After fun close() {
        database.close()
    }

    private suspend fun begin(): DocumentEdit =
        drafts.begin(resource, File(context.cacheDir, "original").apply { writeText("hello") })

    private suspend fun submitted(): DocumentEdit =
        drafts.submit(drafts.finish(begin(), cleanClose = true, authorized = true)) { _, _ -> }

    @Test fun `sealed save restarts once with original identity version and bytes`() =
        runBlocking {
            database.spaceDao().insert(
                SpaceEntity(
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
            database.resourceDao().insert(resource)
            val ready = drafts.finish(begin(), cleanClose = true, authorized = true)
            var submissions = 0
            val recovery =
                DocumentEditReconciler(context, store) { edit ->
                    drafts.submit(edit) { _, source ->
                        submissions++
                        assertEquals(ready.id, source.id)
                        assertEquals("\"v1\"", source.expectedETag)
                        assertEquals("hello", source.payload.readText())
                    }
                }
            recovery.reconcile()
            recovery.reconcile()
            assertEquals(1, submissions)
            assertEquals(DocumentEditState.SUBMITTED, drafts.pending("account").single().state)
        }

    @Test fun `unrelated successful transfer cannot discard a draft`() =
        runBlocking {
            val saved = submitted()
            store.createTransfer(transfer(saved, "SUCCEEDED").copy(accountId = "other"))
            reconciler.reconcile()
            assertEquals(saved, drafts.pending("account").single())
        }

    @Test fun `restart leaves unfinished edits untouched and never uploads them`() =
        runBlocking {
            val open = begin()
            reconciler.reconcile()
            assertEquals(open, drafts.pending("account").single())
        }

    @Test fun `sealed edit for an unavailable space requires review`() =
        runBlocking {
            drafts.finish(begin(), cleanClose = true, authorized = true)
            reconciler.reconcile()
            assertEquals(DocumentEditState.REVIEW, drafts.pending("account").single().state)
        }

    @Test fun `missing upload history is not treated as successful delivery`() =
        runBlocking {
            val saved = submitted()
            reconciler.reconcile()
            assertEquals(saved, drafts.pending("account").single())
        }

    @Test fun `successful upload releases its retained draft`() =
        runBlocking {
            val saved = submitted()
            store.createTransfer(transfer(saved, "SUCCEEDED"))
            reconciler.reconcile()
            assertTrue(drafts.pending("account").isEmpty())
        }

    @Test fun `cancelled upload keeps draft for review instead of requeuing it`() =
        runBlocking {
            val saved = submitted()
            store.createTransfer(transfer(saved, "CANCELLED"))
            reconciler.reconcile()
            assertEquals(DocumentEditState.REVIEW, drafts.pending("account").single().state)
            assertEquals("CANCELLED", store.transfer(saved.id)?.state)
        }

    private fun transfer(
        edit: DocumentEdit,
        state: String,
    ) = TransferEntity(
        id = edit.id,
        accountId = edit.accountId,
        spaceId = edit.spaceId,
        resourceId = edit.resourceId,
        direction = "UPLOAD",
        sourceUri = null,
        destinationPath = edit.path,
        displayName = edit.name,
        mimeType = edit.mimeType,
        bytesTotal = 5,
        state = state,
        createdAtEpochMillis = 0,
        updatedAtEpochMillis = 0,
    )
}
