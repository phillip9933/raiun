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
import java.util.Locale

/** Actual Android index/JCA/metadata codec; synthetic navigation rows, not live server routing acceptance. */
@RunWith(AndroidJUnit4::class)
class BoundaryDestinationSnapshotAndroidTest {
    @Test fun nativeChooserSortPreservesWireTiesAndLateMarkerIdentityWithoutIssuingContentCapabilities() =
        runBlocking<Unit> {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val before = stages(context.noBackupFilesDir)
            val previous = Locale.getDefault()
            var allowed = true
            val names =
                (0 until 333)
                    .map { mask ->
                        "nativecase"
                            .mapIndexed { bit, character ->
                                if (mask and (1 shl bit) == 0) character else character.uppercaseChar()
                            }.joinToString("")
                    }.reversed() + listOf("İ", "i\u0307", "I", "i", "é", "e\u0301")
            val wire =
                names.mapIndexed { number, name ->
                    BoundaryDestinationFolder("actual-folder-$number", "parent/$name", name, number % 43 == 0)
                }
            try {
                Locale.setDefault(Locale.forLanguageTag("tr-TR"))
                val snapshot =
                    captureBoundaryDestinationFolders(context, "parent", {
                        if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied)
                    }) { emit -> wire.forEach(emit) }
                try {
                    val expected = wire.sortedBy { it.name.lowercase(Locale.ROOT) }
                    assertEquals(expected.size.toLong(), snapshot.totalCount)
                    val actual = mutableListOf<BoundaryDestinationFolder>()
                    while (actual.size < snapshot.totalCount) {
                        val page = snapshot.page(actual.size.toLong(), 73)
                        assertTrue(page.size in 1..73)
                        actual += page
                    }
                    assertEquals(expected, actual)
                    assertTrue(actual.drop(256).any(BoundaryDestinationFolder::isVaultRoot))
                    val created = stages(context.noBackupFilesDir) - before
                    assertEquals(1, created.size)
                    File(context.noBackupFilesDir, created.single()).listFiles().orEmpty().forEach { file ->
                        if (file.isFile) {
                            val disk = file.readBytes().toString(Charsets.ISO_8859_1)
                            assertFalse(disk.contains("actual-folder-"))
                            assertFalse(disk.contains("parent/native"))
                        }
                    }
                    allowed = false
                    val failure = assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
                    assertEquals(OpenCloudError.AccessDenied, failure.error)
                } finally {
                    snapshot.close()
                }
                assertEquals(before, stages(context.noBackupFilesDir))
            } finally {
                Locale.setDefault(previous)
            }
        }

    private fun stages(root: File): Set<String> =
        root
            .listFiles()
            .orEmpty()
            .filter { it.isDirectory && it.name.startsWith("vault-directory-") }
            .map(File::getName)
            .toSet()
}
