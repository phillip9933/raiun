package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Production store on Android SQLite/JCA with synthetic descriptors; not live DAV/provider acceptance. */
@RunWith(AndroidJUnit4::class)
class BoundaryDirectorySnapshotAndroidTest {
    @Test fun nativeSqlitePagesFindsAndRevokesOnlyItsOwnedEncryptedStage() =
        runBlocking<Unit> {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val expected =
                (0 until 333).map { number ->
                    val name = (if (number % 17 == 0) "." else "") + "native-private-child-$number.txt"
                    BoundaryEntry(
                        "native-id-$number",
                        "folder/$name",
                        name,
                        number % 7 == 0,
                        if (number % 7 == 0) 0 else number.toLong() + 1,
                        "\"native-$number\"",
                        null,
                    )
                }
            val before = stageNames(context.noBackupFilesDir)
            var allowed = true
            val snapshot =
                captureBoundaryDirectory(context, "folder", {
                    if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied)
                }) { emit -> expected.forEach(emit) }
            val created = stageNames(context.noBackupFilesDir) - before
            assertEquals(1, created.size)
            val stage = File(context.noBackupFilesDir, created.single())
            try {
                assertEquals(expected.size.toLong(), snapshot.totalCount)
                val actual = mutableListOf<BoundaryEntry>()
                var sequence = 0L
                while (sequence < snapshot.totalCount) {
                    val page = snapshot.page(sequence, 73)
                    assertTrue(page.size in 1..73)
                    actual += page
                    sequence += page.size
                }
                assertEquals(expected, actual)
                assertEquals(expected.size, actual.map(BoundaryEntry::id).toSet().size)
                assertTrue(snapshot.page(snapshot.totalCount).isEmpty())
                for (index in listOf(0, 72, 73, 255, 332)) {
                    assertEquals(expected[index], snapshot.findById(expected[index].id))
                }
                assertNull(snapshot.findById("not-present"))
                val disk = stage.readBytes().toString(Charsets.ISO_8859_1)
                assertFalse(disk.contains("native-private-child"))
                assertFalse(disk.contains("native-id-"))
                allowed = false
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { snapshot.findById(expected.first().id) }
                    }
                assertEquals(OpenCloudError.AccessDenied, failure.error)
                assertFalse(stage.exists())
                assertFalse(File(stage.path + ".owner").exists())
            } finally {
                snapshot.close()
            }
            assertEquals(before, stageNames(context.noBackupFilesDir))
            val closed = captureBoundaryDirectory(context, "folder", {}) { emit -> emit(expected.first()) }
            closed.close()
            assertThrows(OpenCloudException::class.java) { runBlocking { closed.page() } }
            assertEquals(before, stageNames(context.noBackupFilesDir))
        }

    private fun stageNames(root: File): Set<String> =
        root
            .listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.startsWith("backup-traversal-") && it.name.endsWith(".db") }
            .map(File::getName)
            .toSet()
}
