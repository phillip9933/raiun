package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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
class BoundaryNameIndexTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun emptyInventoryReservesOnceAndDuplicatePreloadPreservesSetSemantics() =
        runBlocking {
            captureBoundaryNames(context, "", {}) {}.use {
                assertTrue(it.reserve("first"))
                assertFalse(it.reserve("first"))
            }
            captureBoundaryNames(context, "folder", {}) { emit -> repeat(3) { emit("exists") } }.use {
                assertFalse(it.reserve("exists"))
                assertTrue(it.reserve("new"))
                assertFalse(it.reserve("new"))
            }
        }

    @Test fun completeLargeParentAndNumberedCollisionsArePreloadedOnlyOnce() =
        runBlocking {
            var producerCalls = 0
            captureBoundaryNames(context, "folder", {}) { emit ->
                producerCalls++
                emit("photo.jpg")
                repeat(2_049) { emit("photo (${it + 1}).jpg") }
            }.use {
                assertFalse(it.reserve("photo.jpg"))
                for (index in 1..2_049) assertFalse(it.reserve("photo ($index).jpg"))
                assertTrue(it.reserve("photo (2050).jpg"))
                assertFalse(it.reserve("photo (2050).jpg"))
            }
            assertEquals(1, producerCalls)
        }

    @Test fun utf8MembershipIsExactWithoutCaseOrUnicodeNormalization() =
        runBlocking {
            val existing = listOf("File", "é", "K", "😀", "", ".hidden")
            captureBoundaryNames(context, "folder", {}) { emit -> existing.forEach(emit) }.use { index ->
                for (name in existing) assertFalse(index.reserve(name))
                for (name in listOf("file", "e\u0301", "K", "😃")) {
                    assertTrue(index.reserve(name))
                    assertFalse(index.reserve(name))
                }
            }
        }

    @Test fun concurrentCandidatesShareOneAtomicReservation() =
        runBlocking {
            captureBoundaryNames(context, "folder", {}) {}.use { index ->
                val results = List(32) { async { index.reserve("same candidate") } }.awaitAll()
                assertEquals(1, results.count { it })
                assertFalse(index.reserve("same candidate"))
            }
        }

    @Test fun closingWhileAuthorizationSuspendsCannotReturnAReservationOrRetainItsStage() =
        runBlocking {
            val before = spillFiles()
            var pause = false
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val index =
                captureBoundaryNames(context, "folder", {
                    if (pause) {
                        entered.complete(Unit)
                        release.await()
                    }
                }) {}
            pause = true
            val pending =
                async {
                    try {
                        index.reserve("late")
                        null
                    } catch (failure: OpenCloudException) {
                        failure.error
                    }
                }
            withTimeout(5_000) { entered.await() }
            index.close()
            release.complete(Unit)
            assertEquals(OpenCloudError.PreconditionFailed, withTimeout(5_000) { pending.await() })
            assertEquals(before, spillFiles())
        }

    @Test fun finalCaptureCancellationRemovesTheUnpublishedOwnedStage() =
        runBlocking {
            val before = spillFiles()
            val job =
                async {
                    var checks = 0
                    captureBoundaryNames(context, "folder", {
                        checks++
                        if (checks == 2) currentCoroutineContext().cancel()
                    }) { emit -> repeat(333) { emit("private-$it") } }
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

    @Test fun producerFailureNeverPublishesAPrefixOfTheParentNames() =
        runBlocking {
            val before = spillFiles()
            var refused = false
            try {
                captureBoundaryNames(context, "folder", {}) { emit ->
                    repeat(333) { emit("private-$it") }
                    throw IOException("synthetic invalid final response")
                }.close()
            } catch (_: IOException) {
                refused = true
            }
            assertTrue(refused)
            assertEquals(before, spillFiles())
        }

    @Test fun diskContainsOnlyMembershipTokensAndClosePreservesAnIndependentSibling() =
        runBlocking {
            val before = spillFiles()
            val existing = "private-parent-filename-marker"
            val candidate = "private-selected-candidate-marker"
            val first = captureBoundaryNames(context, "folder", {}) { it(existing) }
            val owned = spillFiles() - before
            val sibling = captureBoundaryNames(context, "folder", {}) { it("sibling") }
            try {
                assertTrue(first.reserve(candidate))
                val database = owned.single { it.extension == "db" }
                val bytes = database.readBytes().toString(Charsets.ISO_8859_1)
                assertFalse(bytes.contains(existing))
                assertFalse(bytes.contains(candidate))
                first.close()
                first.close()
                assertTrue(owned.none(File::exists))
                assertFalse(sibling.reserve("sibling"))
                assertTrue(sibling.reserve("still available"))
            } finally {
                first.close()
                sibling.close()
            }
            assertEquals(before, spillFiles())
        }

    @Test fun missingMembershipRowsAreRefusedBeforeAdmittingAnotherReservation() =
        runBlocking {
            val before = spillFiles()
            val index =
                captureBoundaryNames(context, "folder", {}) {
                    it("first")
                    it("second")
                }
            val database = (spillFiles() - before).single { it.extension == "db" }
            SQLiteDatabase.openDatabase(database.path, null, SQLiteDatabase.OPEN_READWRITE).use {
                it.execSQL("DELETE FROM name WHERE rowid = (SELECT MIN(rowid) FROM name)")
            }
            var error: OpenCloudError? = null
            try {
                index.reserve("candidate")
            } catch (
                failure: OpenCloudException,
            ) {
                error = failure.error
            } finally {
                index.close()
            }
            assertEquals(OpenCloudError.InvalidResponse, error)
            assertEquals(before, spillFiles())
        }

    @Test fun malformedUtf16IsRefusedRatherThanAliasedToReplacementBytes() =
        runBlocking {
            val before = spillFiles()
            for (name in listOf("\uD800", "\uD801", "bad\uDC00")) {
                val index = captureBoundaryNames(context, "folder", {}) { it("?") }
                var error: OpenCloudError? = null
                try {
                    index.reserve(name)
                } catch (
                    failure: OpenCloudException,
                ) {
                    error = failure.error
                } finally {
                    index.close()
                }
                assertEquals(OpenCloudError.InvalidResponse, error)
                assertEquals(before, spillFiles())
            }
        }

    private fun spillFiles(): Set<File> =
        context.noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("backup-traversal-") }
            .toSet()
}
