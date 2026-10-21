package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BackupScanStoreTest {
    private val pair =
        FolderBackupEntity(
            "pair",
            "a",
            "s",
            "content://source",
            destinationPath = "/a_%",
            mediaType = "ALL",
            wifiOnly = false,
            chargingOnly = false,
            deleteAfterUpload = false,
        )

    @Test fun `destination changes advance receipt namespace while unchanged settings keep it`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val scans = BackupScanStore(db)
                scans.save(pair)
                val original = requireNotNull(db.folderBackupDao().findById(pair.id))
                assertEquals(0L, original.destinationRevision)
                db.backupReceiptDao().save(BackupReceipt(pair.id, "legacy-receipt", acceptedSignature = "accepted"))

                scans.save(original.copy(wifiOnly = true))
                assertEquals(0L, db.folderBackupDao().findById(pair.id)?.destinationRevision)
                assertEquals("accepted", db.backupReceiptDao().find(pair.id, "legacy-receipt")?.acceptedSignature)

                scans.save(original.copy(exclusionPatterns = "Private/"))
                assertEquals(0L, db.folderBackupDao().findById(pair.id)?.destinationRevision)
                assertEquals("accepted", db.backupReceiptDao().find(pair.id, "legacy-receipt")?.acceptedSignature)

                scans.save(original.copy(spaceId = "different"))
                val moved = requireNotNull(db.folderBackupDao().findById(pair.id))
                assertEquals(1L, moved.destinationRevision)
                assertEquals(null, db.backupReceiptDao().find(pair.id, "legacy-receipt"))
                // A stale scan can write its old receipt after the edit; the revision still isolates it.
                db.backupReceiptDao().save(BackupReceipt(pair.id, "legacy-receipt", acceptedSignature = "late"))
                assertEquals(1L, db.folderBackupDao().findById(pair.id)?.destinationRevision)
                scans.save(moved.copy(destinationPath = "/new"))
                assertEquals(2L, db.folderBackupDao().findById(pair.id)?.destinationRevision)
            } finally {
                db.close()
            }
        }

    @Test fun `vault exclusion disables overlapping pairs with literal boundaries`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val dao = db.folderBackupDao()
                listOf(
                    pair,
                    pair.copy(id = "child", sourceTreeUri = "content://child", destinationPath = "/a_%/child"),
                    pair.copy(id = "root", sourceTreeUri = "content://root", destinationPath = "/"),
                    pair.copy(id = "neighbor", sourceTreeUri = "content://neighbor", destinationPath = "/a_%more"),
                    pair.copy(id = "other", accountId = "b"),
                ).forEach { dao.upsert(it) }
                dao.disableVault("a", "s", "/a_%")
                listOf("pair", "child", "root").forEach { assertFalse(requireNotNull(dao.findById(it)).enabled) }
                assertTrue(requireNotNull(dao.findById("neighbor")).enabled)
                assertTrue(requireNotNull(dao.findById("other")).enabled)
                FileBrowserStore(db).replaceRemoteSpaces("a", emptyList(), excludedVaultIds = setOf("s"))
                assertFalse(requireNotNull(dao.findById("neighbor")).enabled)
            } finally {
                db.close()
            }
        }

    @Test fun `stale scans cannot enqueue or resurrect pairs`() =
        runTest {
            val db =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val dao = db.folderBackupDao()
                val scans = BackupScanStore(db)
                db.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                db.spaceDao().upsertAll(
                    listOf(SpaceEntity("a", "s", "Space", "personal", null, null, "root", null, null, null)),
                )
                dao.upsert(pair)
                val transfer =
                    TransferEntity(
                        "transfer",
                        "a",
                        "s",
                        null,
                        "UPLOAD",
                        "content://file",
                        "/a_%/file",
                        "file",
                        null,
                        1,
                        createdAtEpochMillis = 0,
                        updatedAtEpochMillis = 0,
                    )
                assertEquals("transfer", scans.enqueue(pair, transfer).id)
                for (replacement in listOf(
                    pair.copy(enabled = false),
                    pair.copy(destinationPath = "/elsewhere"),
                    pair.copy(exclusionPatterns = "Private/"),
                    null,
                )) {
                    if (replacement == null) dao.delete(pair.id) else dao.upsert(replacement)
                    var rejected = false
                    try {
                        scans.enqueue(pair, transfer.copy(id = "stale"))
                    } catch (
                        _: IllegalArgumentException,
                    ) {
                        rejected =
                            true
                    }
                    assertTrue(rejected)
                    scans.complete(pair, 999)
                    assertEquals(replacement, dao.findById(pair.id))
                    assertEquals(null, db.transferDao().findById("stale"))
                }
                dao.upsert(pair)
                scans.complete(pair, 123)
                assertEquals(123L, dao.findById(pair.id)?.lastSafeScanEpochMillis)
            } finally {
                db.close()
            }
        }
}
