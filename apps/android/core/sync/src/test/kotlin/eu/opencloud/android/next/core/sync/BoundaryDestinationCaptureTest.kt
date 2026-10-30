package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BoundaryDestinationCaptureTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun duplicateIdsOrCanonicalPathsRejectTheEntireCaptureAndDeleteOwnedStages() {
        val first = BoundaryDestinationFolder("first", "parent/First", "First", false)
        val duplicates =
            listOf(
                BoundaryDestinationFolder("first", "parent/Second", "Second", false),
                BoundaryDestinationFolder("second", "/parent/First/", "First", true),
            )
        duplicates.forEach { duplicate ->
            val before = ownedStages()
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking {
                        captureBoundaryDestinationFolders(context, "parent", {}) { emit ->
                            emit(first)
                            emit(duplicate)
                        }
                    }
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertEquals(before, ownedStages())
        }
    }

    @Test fun nonChildAndInvalidUnicodeMetadataNeverPublishAChooserSnapshot() {
        val invalid =
            listOf(
                BoundaryDestinationFolder("id", "other/First", "First", false),
                BoundaryDestinationFolder("id", "parent/..", "..", false),
                BoundaryDestinationFolder("id", "parent/\uD800", "\uD800", true),
            )
        invalid.forEach { folder ->
            val before = ownedStages()
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { captureBoundaryDestinationFolders(context, "parent", {}) { it(folder) } }
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertEquals(before, ownedStages())
        }
    }

    private fun ownedStages(): Set<String> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("vault-directory-") || it.name.startsWith("backup-traversal-") }
            .map { it.name }
            .toSet()
}
