package eu.opencloud.android.next.core.sync

import androidx.room.Room
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteTrashResource
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferMutationGuardTest {
    @Test fun `excluded and stale mutation requests stop before HTTP`() =
        runTest {
            MockWebServer().use { server ->
                val context = RuntimeEnvironment.getApplication()
                val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
                WorkManagerTestInitHelper.initializeTestWorkManager(
                    context,
                    Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
                )
                try {
                    val store = FileBrowserStore(database)
                    database.accountDao().upsert(
                        AccountEntity("a", server.url("/").toString().trimEnd('/'), "u", "U", "BASIC", false),
                    )
                    database.spaceDao().upsertAll(
                        listOf(
                            SpaceEntity(
                                "a",
                                "s",
                                "Space",
                                "personal",
                                null,
                                null,
                                "root",
                                server.url("/dav").toString(),
                                null,
                                null,
                            ),
                        ),
                    )
                    val file = resource("file", "/vault/file", "v1")
                    val visible = resource("visible", "/visible/file", "v1")
                    database.resourceDao().upsert(file)
                    database.resourceDao().upsert(visible)
                    database.vaultExclusionDao().record(VaultExclusion("a", "s", "/vault"))
                    database.vaultExclusionDao().record(VaultExclusion("a", "s", "/visible/new"))
                    val manager = TransferManager(context, store, WorkManager.getInstance(context))
                    val trashItem = RemoteTrashResource("trash", "s", "file", "/vault/file", false, 0)

                    assertRejected("Encrypted vault locations are unavailable.") { manager.delete(file) }
                    assertPrecondition { manager.delete(visible.copy(eTag = "old")) }
                    assertRejected("Encrypted vault locations are unavailable.") {
                        manager.renameFile(visible, "new")
                    }
                    assertRejected("Encrypted vault locations are unavailable.") { manager.setFavorite(file, true) }
                    assertRejected("Encrypted vault locations are unavailable.") {
                        manager.createFolder("a", "s", null, "vault")
                    }
                    assertRejected("Encrypted vault locations are unavailable.") {
                        TrashManager(context, store).restore("a", trashItem)
                    }
                    database.spaceDao().upsertAll(
                        listOf(
                            SpaceEntity(
                                "a",
                                "s",
                                "Space",
                                "personal",
                                null,
                                null,
                                "root",
                                server.url("/dav").toString(),
                                null,
                                null,
                                isDisabled = true,
                            ),
                        ),
                    )
                    assertRejected("The space is unavailable.") {
                        TrashManager(context, store).permanentlyDelete("a", trashItem)
                    }
                    database.spaceDao().upsertAll(
                        listOf(
                            SpaceEntity(
                                "a",
                                "s",
                                "Space",
                                "personal",
                                null,
                                null,
                                "root",
                                server.url("/dav").toString(),
                                null,
                                null,
                            ),
                        ),
                    )
                    database.accountDao().upsert(
                        AccountEntity(
                            "a",
                            server.url("/").toString().trimEnd('/'),
                            "u",
                            "U",
                            "BASIC",
                            false,
                            isActive = false,
                        ),
                    )
                    assertRejected("The account is unavailable.") {
                        TrashManager(context, store).permanentlyDelete("a", trashItem)
                    }
                    assertEquals(0, server.requestCount)
                } finally {
                    WorkManagerTestInitHelper.closeWorkDatabase()
                    database.close()
                }
            }
        }

    private fun resource(
        id: String,
        path: String,
        eTag: String,
    ) = ResourceEntity(
        "a",
        "s",
        id,
        null,
        path,
        path.substringAfterLast('/'),
        ResourceKind.FILE,
        null,
        1,
        eTag,
        0,
        0,
    )

    private suspend fun assertRejected(
        expectedMessage: String,
        action: suspend () -> Unit,
    ) {
        var actualMessage: String? = null
        try {
            action()
        } catch (exception: IllegalStateException) {
            actualMessage = exception.message
        } catch (exception: IllegalArgumentException) {
            actualMessage = exception.message
        }
        assertEquals(expectedMessage, actualMessage)
    }

    private suspend fun assertPrecondition(action: suspend () -> Unit) {
        var preconditionFailed = false
        try {
            action()
        } catch (exception: OpenCloudException) {
            preconditionFailed = exception.error == OpenCloudError.PreconditionFailed
        }
        assertTrue(preconditionFailed)
    }
}
