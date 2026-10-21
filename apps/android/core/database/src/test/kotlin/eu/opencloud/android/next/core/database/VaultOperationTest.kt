package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class VaultOperationTest {
    private val operation =
        FileOperationEntity(
            "op",
            "a",
            "s",
            "t",
            "file",
            null,
            null,
            "https://example.test/s",
            "https://example.test/t",
            "/parent/a_%/file",
            "/target",
            "\"v1\"",
            true,
            state = "SENT",
            fingerprint = "digest",
            lease = "old",
        )

    @Test fun `folder exclusion blocks overlapping operations and cannot revive old leases or pins`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                val dao = database.fileOperationDao()
                dao.insert(operation)
                dao.insert(operation.copy(id = "ancestor", sourcePath = "/parent", sourceFolder = true))
                dao.insert(operation.copy(id = "neighbor", sourcePath = "/parent/a_%more/file"))
                dao.insert(operation.copy(id = "other-account", accountId = "b"))
                dao.insert(
                    operation.copy(
                        id = "destination",
                        sourceSpaceId = "t",
                        destinationSpaceId = "s",
                        destinationPath = "/parent/a_%/new",
                    ),
                )
                dao.insert(operation.copy(id = "complete", state = "SUCCEEDED"))
                database.openHelper.writableDatabase.execSQL("INSERT INTO operation_pins VALUES ('op', '/child')")
                dao.blockVault("a", "s", "/parent/a_%")
                database.pendingPinDao().clearBlockedOperations("a")
                for (id in listOf("op", "ancestor", "destination")) {
                    assertEquals("BLOCKED_VAULT", dao.find(id)?.state)
                    assertEquals(null, dao.find(id)?.lease)
                    dao.retry(id, "a")
                    assertEquals(0, dao.claim(id, "new"))
                    assertEquals(0, dao.deleting(id, "old"))
                    assertEquals(0, dao.finish(id, "old", "SUCCEEDED", null))
                }
                assertFalse(FileOperationStore(database).complete(operation, "old"))
                database.pendingPinDao().activate("a", "t", "/target", "op")
                assertEquals(emptyList<PendingPinEntity>(), database.pendingPinDao().pending())
                assertEquals("SENT", dao.find("neighbor")?.state)
                assertEquals("SENT", dao.find("other-account")?.state)
                assertEquals("SUCCEEDED", dao.find("complete")?.state)
                FileOperationStore(database).dismiss("op", "b")
                assertEquals("BLOCKED_VAULT", dao.find("op")?.state)
                FileOperationStore(database).dismiss("op", "a")
                assertEquals(null, dao.find("op"))
            } finally {
                database.close()
            }
        }

    @Test fun `drive reconciliation blocks source and destination operations but preserves history`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val dao = database.fileOperationDao()
                dao.insert(operation)
                dao.insert(operation.copy(id = "destination", sourceSpaceId = "t", destinationSpaceId = "s"))
                dao.insert(operation.copy(id = "neighbor", sourceSpaceId = "t"))
                dao.insert(operation.copy(id = "complete", state = "SUCCEEDED"))
                FileBrowserStore(database).replaceRemoteSpaces("a", emptyList(), excludedVaultIds = setOf("s"))
                assertEquals("BLOCKED_VAULT", dao.find("op")?.state)
                assertEquals("BLOCKED_VAULT", dao.find("destination")?.state)
                assertEquals("SENT", dao.find("neighbor")?.state)
                assertEquals("SUCCEEDED", dao.find("complete")?.state)
            } finally {
                database.close()
            }
        }
}
