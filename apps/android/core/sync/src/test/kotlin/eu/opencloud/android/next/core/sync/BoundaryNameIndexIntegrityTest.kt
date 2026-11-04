package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
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

@RunWith(RobolectricTestRunner::class)
class BoundaryNameIndexIntegrityTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun lostPrivateMembershipRowsAreRefusedRatherThanReturningAFreshReservation() =
        runBlocking<Unit> {
            val before = stageNames()
            val index =
                captureBoundaryNames(context, "", {}) { emit ->
                    emit("already-present.txt")
                    emit("another.txt")
                }
            try {
                val created = stageNames() - before
                assertEquals(1, created.size)
                val file = File(context.noBackupFilesDir, created.single())
                SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use {
                    it.execSQL("DELETE FROM name WHERE identity IN (SELECT identity FROM name LIMIT 1)")
                }
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { index.reserve("new.txt") }
                    }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            } finally {
                index.close()
            }
            assertEquals(before, stageNames())
        }

    @Test fun closeAfterReservationButBeforeGuardedDeliveryNeverPublishesSuccess() =
        runBlocking<Unit> {
            val before = stageNames()
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var reserving = false
            var checks = 0
            val index =
                captureBoundaryNames(context, "", {
                    if (reserving && ++checks == 2) {
                        entered.complete(Unit)
                        release.await()
                    }
                }) { emit -> emit("existing.txt") }
            try {
                reserving = true
                val pending =
                    async {
                        try {
                            index.reserve("new.txt")
                            false
                        } catch (_: OpenCloudException) {
                            true
                        }
                    }
                withTimeout(5_000) { entered.await() }
                val closing = async(Dispatchers.IO) { index.close() }
                try {
                    withTimeout(5_000) { closing.await() }
                } finally {
                    release.complete(Unit)
                }
                assertTrue(withTimeout(5_000) { pending.await() })
                assertThrows(OpenCloudException::class.java) { runBlocking { index.reserve("later.txt") } }
            } finally {
                release.complete(Unit)
                index.close()
            }
            assertEquals(before, stageNames())
        }

    private fun stageNames(): Set<String> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.startsWith("backup-traversal-") && it.name.endsWith(".db") }
            .map(File::getName)
            .toSet()
}
