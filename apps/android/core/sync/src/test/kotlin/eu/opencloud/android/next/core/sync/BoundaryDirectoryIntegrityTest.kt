package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/** Independent corruption tests: mutate only the fresh stage owned by this test, never production APIs. */
@RunWith(RobolectricTestRunner::class)
class BoundaryDirectoryIntegrityTest {
    private val context = RuntimeEnvironment.getApplication()
    private val entries =
        (1..3).map { number ->
            BoundaryEntry("id-$number", "folder/file-$number", "file-$number", false, number.toLong(), "\"v$number\"")
        }

    @Test fun authenticatedRecordsRejectChangedSequenceIdentityPathTokenAndCiphertext() =
        runBlocking<Unit> {
            val changes: List<(SQLiteDatabase) -> Unit> =
                listOf(
                    { it.execSQL("UPDATE entry SET sequence = sequence + 100 WHERE sequence = 1") },
                    { it.execSQL("UPDATE entry SET identity = 'changed-token' WHERE sequence = 1") },
                    { it.execSQL("UPDATE entry SET pathIdentity = 'changed-path-token' WHERE sequence = 1") },
                    { db ->
                        val body =
                            db.rawQuery("SELECT payload FROM entry WHERE sequence = 1", null).use {
                                check(it.moveToFirst())
                                it.getBlob(0)
                            }
                        body[body.lastIndex] = (body.last().toInt() xor 1).toByte()
                        db.execSQL("UPDATE entry SET payload = ? WHERE sequence = 1", arrayOf(body))
                    },
                )
            for (change in changes) {
                val before = stageNames()
                val snapshot = captureBoundaryDirectory(context, "folder", {}) { emit -> entries.forEach(emit) }
                try {
                    val stage = ownedStage(before)
                    SQLiteDatabase.openDatabase(stage.path, null, SQLiteDatabase.OPEN_READWRITE).use(change)
                    assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
                } finally {
                    snapshot.close()
                }
                assertEquals(before, stageNames())
            }
        }

    @Test fun frozenCountDoesNotAllowDeletedMiddleOrTailRowsToLookLikeACompleteShortPage() =
        runBlocking<Unit> {
            for (removed in listOf(2, 3)) {
                val before = stageNames()
                val snapshot = captureBoundaryDirectory(context, "folder", {}) { emit -> entries.forEach(emit) }
                try {
                    assertEquals(3L, snapshot.totalCount)
                    SQLiteDatabase.openDatabase(ownedStage(before).path, null, SQLiteDatabase.OPEN_READWRITE).use {
                        it.execSQL("DELETE FROM entry WHERE sequence = ?", arrayOf(removed))
                    }
                    assertEquals(3L, snapshot.totalCount)
                    assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page(0, 128) } }
                } finally {
                    snapshot.close()
                }
                assertEquals(before, stageNames())
            }
        }

    @Test fun closeDuringSuspendedGuardPreventsLatePageAndLookupDeliveryWithoutHoldingCursorLock() =
        runBlocking<Unit> {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var wait = false
            val snapshot =
                captureBoundaryDirectory(context, "folder", {
                    if (wait) {
                        entered.complete(Unit)
                        release.await()
                    }
                }) { emit -> entries.forEach(emit) }
            try {
                wait = true
                val pending =
                    async {
                        try {
                            snapshot.page()
                            false
                        } catch (_: OpenCloudException) {
                            true
                        }
                    }
                withTimeout(5_000) { entered.await() }
                val closing = async(Dispatchers.IO) { snapshot.close() }
                try {
                    withTimeout(5_000) { closing.await() }
                } finally {
                    release.complete(Unit)
                }
                assertTrue(withTimeout(5_000) { pending.await() })
                assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.findById(entries.first().id) } }
            } finally {
                release.complete(Unit)
                snapshot.close()
            }
        }

    private fun stageNames(): Set<String> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.startsWith("backup-traversal-") && it.name.endsWith(".db") }
            .map(File::getName)
            .toSet()

    private fun ownedStage(before: Set<String>): File {
        val created = stageNames() - before
        check(created.size == 1)
        return File(context.noBackupFilesDir, created.single())
    }
}
