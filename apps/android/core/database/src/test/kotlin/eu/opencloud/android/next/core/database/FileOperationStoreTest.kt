package eu.opencloud.android.next.core.database

import androidx.room.Room
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class FileOperationStoreTest {
    @Test fun `enqueue rejects excluded paths and folders containing exclusions`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                val space =
                    SpaceEntity(
                        "a",
                        "s",
                        "Space",
                        "project",
                        null,
                        null,
                        "root",
                        "https://example.test/dav",
                        null,
                        null,
                    )
                database.spaceDao().insert(space)
                database.vaultExclusionDao().record(VaultExclusion("a", "s", "/source/private"))
                database.vaultExclusionDao().record(VaultExclusion("a", "s", "/blocked-target"))
                val operations = FileOperationStore(database)

                fun operation(
                    id: String,
                    sourcePath: String,
                    destinationPath: String,
                    sourceFolder: Boolean = false,
                ) = FileOperationEntity(
                    id,
                    "a",
                    "s",
                    "s",
                    id,
                    null,
                    null,
                    space.rootWebDavUrl!!,
                    space.rootWebDavUrl,
                    sourcePath,
                    destinationPath,
                    "\"v1\"",
                    move = true,
                    sourceFolder = sourceFolder,
                )

                val nestedSource = operation("nested", "/source/private/file", "/copy", sourceFolder = false)
                val containingSource = operation("containing", "/source", "/copy", sourceFolder = true)
                val blockedDestination = operation("destination", "/plain", "/blocked-target/file")
                for (blocked in listOf(nestedSource, containingSource, blockedDestination)) {
                    assertTrue(runCatching { operations.enqueue(blocked) }.isFailure)
                }
                val boundarySibling = operation("boundary", "/source/private-sibling", "/allowed")
                operations.enqueue(boundarySibling)

                assertEquals(null, operations.dao.find("nested"))
                assertEquals(null, operations.dao.find("containing"))
                assertEquals(null, operations.dao.find("destination"))
                assertEquals("QUEUED", operations.dao.find("boundary")?.state)
                assertTrue(database.pendingPinDao().pending().isEmpty())
            } finally {
                database.close()
            }
        }

    @Test fun `move pins survive intervening discovery and only owner can complete operation`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val store = FileBrowserStore(database)
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                val space =
                    SpaceEntity(
                        "a",
                        "s",
                        "Space",
                        "project",
                        null,
                        null,
                        "root",
                        "https://example.test/dav",
                        null,
                        null,
                    )
                database.spaceDao().insert(space)
                database.spaceDao().insert(space.copy(driveId = "t"))
                val file =
                    ResourceEntity(
                        "a",
                        "s",
                        "f",
                        null,
                        "/file",
                        "file",
                        ResourceKind.FILE,
                        null,
                        5,
                        "\"v1\"",
                        0,
                        0,
                        offlinePinned = true,
                    )
                database.resourceDao().insert(file)
                val operation =
                    FileOperationEntity(
                        "op",
                        "a",
                        "s",
                        "t",
                        "f",
                        null,
                        null,
                        space.rootWebDavUrl!!,
                        space.rootWebDavUrl,
                        "/file",
                        "/copied",
                        "\"v1\"",
                        true,
                    )
                val operations = FileOperationStore(database)
                operations.enqueue(operation)
                operations.dao.claim("op", "owner")
                operations.dao.sent("op", "owner", "digest")
                store.delete("a", "s", "f")
                assertFalse(operations.complete(operation, "stale"))
                assertTrue(database.pendingPinDao().pending().isEmpty())
                assertTrue(operations.complete(operation, "owner"))
                assertEquals(
                    "/copied",
                    database
                        .pendingPinDao()
                        .pending()
                        .single()
                        .path,
                )
                store.replaceFolderSnapshot(
                    "a",
                    "t",
                    null,
                    listOf(
                        file.copy(
                            spaceId = "t",
                            remoteId = "new-id",
                            path = "/copied",
                            name = "copied",
                            offlinePinned = false,
                        ),
                    ),
                )
                assertTrue(requireNotNull(store.resource("a", "t", "new-id")).offlinePinned)
                assertTrue(database.pendingPinDao().pending().isEmpty())
            } finally {
                database.close()
            }
        }
}
