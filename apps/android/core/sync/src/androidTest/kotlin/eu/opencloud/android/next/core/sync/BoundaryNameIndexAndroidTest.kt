package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Synthetic names on production Android SQLite/JCA; conditional server creation remains a separate check. */
@RunWith(AndroidJUnit4::class)
class BoundaryNameIndexAndroidTest {
    @Test fun nativeMembershipReservesExactNamesAndRevokesOnlyItsOwnedHmacStage() =
        runBlocking<Unit> {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val before = stageNames(context.noBackupFilesDir)
            var allowed = true
            var producers = 0
            val index =
                captureBoundaryNames(context, "folder", {
                    if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied)
                }) { emit ->
                    producers++
                    repeat(333) {
                        emit("native-private-name-$it")
                        emit("native-private-name-$it")
                    }
                    emit("é")
                    emit("K")
                    emit("😀")
                }
            val owned = stageNames(context.noBackupFilesDir) - before
            assertEquals(1, owned.size)
            val stage = File(context.noBackupFilesDir, owned.single())
            val sibling = captureBoundaryNames(context, "folder", {}) { it("sibling") }
            try {
                repeat(333) { assertFalse(index.reserve("native-private-name-$it")) }
                assertFalse(index.reserve("é"))
                assertTrue(index.reserve("e\u0301"))
                assertFalse(index.reserve("K"))
                assertTrue(index.reserve("K"))
                assertFalse(index.reserve("😀"))
                assertTrue(index.reserve("native-private-new-candidate"))
                assertFalse(index.reserve("native-private-new-candidate"))
                assertEquals(1, producers)
                val bytes = stage.readBytes().toString(Charsets.ISO_8859_1)
                assertFalse(bytes.contains("native-private-name-"))
                assertFalse(bytes.contains("native-private-new-candidate"))
                allowed = false
                val failure = assertThrows(OpenCloudException::class.java) { runBlocking { index.reserve("revoked") } }
                assertEquals(OpenCloudError.AccessDenied, failure.error)
                assertFalse(stage.exists())
                assertFalse(File(stage.path + ".owner").exists())
                assertFalse(sibling.reserve("sibling"))
                assertTrue(sibling.reserve("independent"))
            } finally {
                index.close()
                sibling.close()
            }
            assertEquals(before, stageNames(context.noBackupFilesDir))
            assertThrows(OpenCloudException::class.java) { runBlocking { index.reserve("closed") } }
        }

    private fun stageNames(root: File): Set<String> =
        root
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("backup-traversal-") && it.name.endsWith(".db") }
            .map(File::getName)
            .toSet()
}
