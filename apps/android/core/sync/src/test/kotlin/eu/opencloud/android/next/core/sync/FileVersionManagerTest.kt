package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteFileVersion
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class FileVersionManagerTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = FileBrowserStore(database)
    private val resource =
        ResourceEntity(
            "versions-test",
            "s",
            "r",
            null,
            "/notes",
            "notes",
            ResourceKind.FILE,
            "text/plain",
            0,
            "\"v1\"",
            0,
            0,
            hasLocalCopy = true,
            localPath = "/cached",
            offlinePinned = true,
        )
    private val manager = FileVersionManager(context, store)

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(
                AccountEntity(resource.accountId, "https://example.test", "u", "User", "BASIC", false),
            )
            database.spaceDao().insert(
                SpaceEntity(
                    resource.accountId,
                    "s",
                    "Personal",
                    "personal",
                    null,
                    null,
                    "root",
                    "https://example.test/remote.php/dav/spaces/s",
                    null,
                    null,
                ),
            )
            database.resourceDao().insert(resource)
        }

    @After fun close() = database.close()

    @Test fun `pending and failed uploads block restore before credentials or network`() {
        listOf("QUEUED", "RUNNING", "RETRY", "FAILED", "CONFLICT").forEach { state ->
            runBlocking {
                store.clearTransfers(resource.accountId)
                store.createTransfer(
                    TransferEntity(
                        "upload",
                        resource.accountId,
                        "s",
                        "r",
                        "UPLOAD",
                        null,
                        "/notes",
                        "notes",
                        "text/plain",
                        0,
                        state = state,
                        createdAtEpochMillis = 0,
                        updatedAtEpochMillis = 0,
                    ),
                )
            }
            val error =
                assertThrows(IllegalStateException::class.java) {
                    runBlocking { manager.restore(resource, RemoteFileVersion("old", null, 0)) }
                }
            assertTrue(error.message.orEmpty().contains("pending uploads"))
        }
    }

    @Test fun `open document edit blocks restore`() {
        val original = File(context.cacheDir, "version-original").apply { writeBytes(byteArrayOf()) }
        runBlocking { DocumentEditStore(context).begin(resource, original) }
        val error =
            assertThrows(IllegalStateException::class.java) {
                runBlocking { manager.restore(resource, RemoteFileVersion("old", null, 0)) }
            }
        assertTrue(error.message.orEmpty().contains("pending edits"))
    }

    @Test fun `restoration invalidates cached bytes but preserves offline selection`() =
        runBlocking {
            store.invalidateFileContent(resource)
            val current = requireNotNull(store.resource(resource.accountId, "s", "r"))
            assertFalse(current.hasLocalCopy)
            assertTrue(current.offlinePinned)
        }
}
