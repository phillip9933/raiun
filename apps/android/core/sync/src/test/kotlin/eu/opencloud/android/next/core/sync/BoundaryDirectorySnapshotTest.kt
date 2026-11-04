package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class BoundaryDirectorySnapshotTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun completeStreamRemainsInCaptureOrderAcrossBoundedPagesAndKeyedLookup() =
        runBlocking {
            val before = spillFiles()
            captureBoundaryDirectory(context, "Folder", {}) { emit ->
                repeat(1_025) { emit(entry(it)) }
            }.use { snapshot ->
                assertEquals(1_025L, snapshot.totalCount)
                var after = 0L
                val identities = mutableListOf<String>()
                while (after < snapshot.totalCount) {
                    val page = snapshot.page(after)
                    assertTrue(page.size in 1..128)
                    identities += page.map { it.id }
                    after += page.size
                }
                assertEquals((0..1_024).map { "id-$it" }, identities)
                assertEquals(entry(1_024), snapshot.findById("id-1024"))
                assertEquals(null, snapshot.findById("missing"))
                assertTrue(snapshot.page(after).isEmpty())
            }
            assertEquals(before, spillFiles())
        }

    @Test fun byteBudgetShortPagesAdvanceByActualCountAndPreserveNullAndEmptyFields() =
        runBlocking {
            val largeVersion = "v".repeat(600_000)
            captureBoundaryDirectory(context, "Folder", {}) { emit ->
                repeat(3) { emit(entry(it).copy(version = largeVersion, mimeType = if (it == 0) null else "")) }
            }.use { snapshot ->
                assertEquals(3L, snapshot.totalCount)
                repeat(3) { index ->
                    val page = snapshot.page(index.toLong())
                    assertEquals(1, page.size)
                    assertEquals("id-$index", page.single().id)
                    assertEquals(largeVersion, page.single().version)
                    assertEquals(if (index == 0) null else "", page.single().mimeType)
                }
            }
        }

    @Test fun hiddenUnicodeNamesAndOriginalPathSpellingPreserveTheExactTuple() =
        runBlocking {
            val hidden = BoundaryEntry("識別😀", "/親/.hidden😀/", ".hidden😀", false, 0, "", null)
            val other = hidden.copy(id = "other", path = "親/other", name = "other", version = null, mimeType = "")
            captureBoundaryDirectory(context, "親", {}) { emit ->
                emit(hidden)
                emit(other)
            }.use {
                assertEquals(listOf(hidden, other), it.page())
                assertEquals(hidden, it.findById(hidden.id))
                assertEquals(other, it.findById(other.id))
            }
        }

    @Test fun malformedInMemoryRecordBytesAreInvalidResponses() {
        for (encoded in listOf(byteArrayOf(), byteArrayOf(0, 0, 0, 1))) {
            var error: OpenCloudError? = null
            try {
                BoundaryDirectoryCodec.decode(encoded)
            } catch (failure: OpenCloudException) {
                error = failure.error
            }
            assertEquals(OpenCloudError.InvalidResponse, error)
        }
    }

    @Test fun duplicateLogicalIdsAndCanonicalPathAliasesFailTheWholeCapture() =
        runBlocking {
            val before = spillFiles()
            val original = entry(0)
            for (duplicate in listOf(
                entry(1).copy(id = original.id),
                original.copy(id = "different"),
                original.copy(id = "alias", path = "/${original.path}/"),
            )) {
                val error =
                    try {
                        captureBoundaryDirectory(context, "Folder", {}) { emit ->
                            emit(original)
                            emit(duplicate)
                        }.close()
                        null
                    } catch (failure: OpenCloudException) {
                        failure.error
                    }
                assertEquals(OpenCloudError.InvalidResponse, error)
                assertEquals(before, spillFiles())
            }
        }

    @Test fun finalProducerFailureNeverPublishesAValidatedPrefixAndRemovesItsStage() =
        runBlocking {
            val before = spillFiles()
            var refused = false
            try {
                captureBoundaryDirectory(context, "Folder", {}) { emit ->
                    repeat(260) { emit(entry(it)) }
                    throw IOException("synthetic malformed final response")
                }.close()
            } catch (_: IOException) {
                refused = true
            }
            assertTrue(refused)
            assertEquals(before, spillFiles())
        }

    @Test fun cancellationAtTheFinalCaptureGuardRemovesTheUnpublishedStage() =
        runBlocking {
            val before = spillFiles()
            val job =
                async {
                    var checks = 0
                    captureBoundaryDirectory(context, "Folder", {
                        checks++
                        if (checks == 2) currentCoroutineContext().cancel()
                    }) { emit -> repeat(260) { emit(entry(it)) } }
                }
            var cancelled = false
            try {
                job.await().close()
            } catch (_: CancellationException) {
                cancelled = true
            }
            assertTrue(cancelled)
            assertEquals(before, spillFiles())
        }

    @Test fun encryptedOwnedStageDoesNotLeakNamesAndClosingItLeavesAnotherSnapshotUsable() =
        runBlocking {
            val before = spillFiles()
            val secret =
                entry(0).copy(
                    id = "private-logical-identity-marker",
                    name = "private-filename-marker",
                    path = "Folder/private-filename-marker",
                    version = "private-version-marker",
                )
            val first = captureBoundaryDirectory(context, "Folder", {}) { it(secret) }
            val firstFiles = spillFiles() - before
            val second = captureBoundaryDirectory(context, "Folder", {}) { it(entry(1)) }
            try {
                val database = firstFiles.single { it.extension == "db" }
                val bytes = database.readBytes().toString(Charsets.ISO_8859_1)
                for (marker in listOf(secret.id, secret.name, secret.version!!)) assertFalse(bytes.contains(marker))
                first.close()
                first.close()
                assertTrue(firstFiles.none(File::exists))
                assertEquals(entry(1), second.findById("id-1"))
            } finally {
                first.close()
                second.close()
            }
            assertEquals(before, spillFiles())
        }

    @Test fun consumerRevocationStopsBeforeTheNextEntryAndClosesTheSnapshot() =
        runBlocking {
            val before = spillFiles()
            var allowed = true
            var consumed = 0
            val snapshot =
                captureBoundaryDirectory(context, "Folder", { check(allowed) }) { emit ->
                    repeat(260) { emit(entry(it)) }
                }
            var refused = false
            try {
                snapshot.forEach {
                    assertEquals(it, snapshot.findById(it.id))
                    consumed++
                    allowed = false
                }
            } catch (_: IllegalStateException) {
                refused = true
            }
            assertTrue(refused)
            assertEquals(1, consumed)
            assertEquals(before, spillFiles())
        }

    @Test fun longVaultPathsRemainSupportedWhileOversizedRecordsFailExplicitly() =
        runBlocking {
            val parent = List(80) { "segment".repeat(8) }.joinToString("/")
            val child = entry(0).copy(path = "$parent/child-0")
            captureBoundaryDirectory(context, parent, {}) { it(child) }.use {
                assertEquals(child, it.findById(child.id))
            }
            val before = spillFiles()
            var error: OpenCloudError? = null
            try {
                captureBoundaryDirectory(context, "Folder", {}) {
                    it(entry(0).copy(version = "x".repeat(BOUNDARY_DIRECTORY_BYTES)))
                }.close()
            } catch (failure: OpenCloudException) {
                error = failure.error
            }
            assertEquals(OpenCloudError.DirectoryListingTooLarge, error)
            assertEquals(before, spillFiles())
        }

    private fun entry(index: Int): BoundaryEntry =
        BoundaryEntry(
            "id-$index",
            "Folder/child-$index",
            "child-$index",
            false,
            index.toLong(),
            "\"version-$index\"",
            "text/plain",
        )

    private fun spillFiles(): Set<File> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("backup-traversal-") }
            .toSet()
}
