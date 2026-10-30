package eu.opencloud.android.next.core.database

import androidx.room.Room
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class TemporaryCopyInventoryTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var directory: File
    private val scopes = mutableListOf<TemporaryCopyScope>()
    private val captureBlock = AtomicReference<CaptureBlock?>()
    private val account = AccountEntity("a", "https://example.test", "user", "User", "BASIC", false)
    private val space = SpaceEntity("a", "space", "Personal", "personal", null, null, "root", null, null, null)

    @Before fun setUp() =
        runBlocking {
            database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).setQueryCallback(
                        { sql, _ -> captureBlock.get()?.awaitCapture(sql) },
                        Executor { it.run() },
                    ).build()
            store = FileBrowserStore(database)
            directory = File(RuntimeEnvironment.getApplication().cacheDir, "inventory-${System.nanoTime()}")
            database.accountDao().upsert(account)
            database.accountDao().upsert(account.copy(id = "other"))
            database.spaceDao().upsertAll(
                listOf(space, space.copy(driveId = ""), space.copy(driveId = "space2")),
            )
        }

    @After fun close() {
        scopes.forEach { it.close() }
        database.close()
        directory.deleteRecursively()
    }

    @Test fun frozenBinaryIdentityPagesProgressWhileOriginalCopiesDisappearAndNewCopiesArrive() =
        runBlocking {
            val rows =
                listOf(row("").copy(spaceId = "")) +
                    (0 until 390).map { index ->
                        row((index / 2).toString().padStart(4, '0')).copy(
                            spaceId = if (index % 2 == 0) "space" else "space2",
                            name = listOf("Name", "name", "ä", "東京", ".hidden")[index % 5],
                            parentId = null,
                        )
                    } +
                    listOf(row("Ä"), row("ä"), row("\uE000"), row("😀"))
            database.resourceDao().insertAll(rows)
            val scope = capture()
            assertTrue(directory.listFiles().orEmpty().any { it.extension == "sqlite" && it.length() > 0 })
            val later = listOf(row("000-before"), row("zz-after"), row("same-copy-new-space").copy(spaceId = "space2"))
            database.resourceDao().insertAll(later)
            val seen = mutableListOf<ResourceEntity>()
            var after: TemporaryCopyKey? = null
            var deleted = 0
            while (true) {
                val page = store.temporaryCopies().page(scope, after)
                if (page.isEmpty()) break
                assertTrue(page.size <= 128)
                page.forEach { expected ->
                    seen += expected
                    assertTrue(store.temporaryCopies().expire(scope, expected) { true })
                    deleted++
                }
                after = page.last().key()
            }
            val binary = Comparator<String> { left, right -> compareBinary(left, right) }
            val expected =
                rows.sortedWith(compareBy<ResourceEntity, String>(binary) { it.spaceId }.thenBy(binary) { it.remoteId })
            assertEquals(expected, seen)
            assertEquals(395, deleted)
            assertEquals(rows.size, seen.map { it.key() }.toSet().size)
            later.forEach { assertEquals(it, store.resource(it.accountId, it.spaceId, it.remoteId)) }
        }

    @Test fun membershipRetainsOriginalDescriptorsAndIncludesHiddenAndExcludedOrdinaryRows() =
        runBlocking {
            val original = row("item").copy(isFavorite = true, createdAtEpochMillis = Long.MIN_VALUE)
            val hidden = row("hidden").copy(name = ".hidden", path = "/vault/hidden")
            database.resourceDao().insertAll(listOf(original, hidden))
            database.vaultExclusionDao().record(VaultExclusion("a", "space", "/vault"))
            val scope = capture()
            val changed = original.copy(localPath = "/newer", eTag = "newer")
            database.resourceDao().update(changed)
            assertEquals(setOf(original, hidden), store.temporaryCopies().page(scope).toSet())
            var callbacks = 0
            assertFalse(
                store.temporaryCopies().expire(scope, original) {
                    callbacks++
                    true
                },
            )
            assertFalse(
                store.temporaryCopies().expire(scope, changed) {
                    callbacks++
                    true
                },
            )
            assertEquals(0, callbacks)
            assertEquals(changed, store.resource("a", "space", "item"))
            assertTrue(store.temporaryCopies().expire(scope, hidden) { true })
            assertEquals(hidden.copy(hasLocalCopy = false, localPath = null), store.resource("a", "space", "hidden"))
        }

    @Test fun completeRowCasRejectsEveryChangedFieldBeforeFilesystemCallback() =
        runBlocking {
            val original = row("cas")
            database.resourceDao().insert(original)
            val scope = capture()
            val mutations =
                listOf(
                    original.copy(parentId = "other-parent"),
                    original.copy(path = "/moved"),
                    original.copy(name = "renamed"),
                    original.copy(kind = ResourceKind.FOLDER),
                    original.copy(mimeType = null),
                    original.copy(sizeBytes = 5),
                    original.copy(eTag = null),
                    original.copy(modifiedAtEpochMillis = 3),
                    original.copy(createdAtEpochMillis = 3),
                    original.copy(isFavorite = true),
                    original.copy(hasLocalCopy = false),
                    original.copy(localPath = "/another-copy"),
                    original.copy(offlinePinned = true),
                )
            for (changed in mutations) {
                database.resourceDao().update(changed)
                assertFalse(store.temporaryCopies().expire(scope, original) { error("Rejected CAS invoked callback") })
                assertEquals(changed, store.resource("a", "space", "cas"))
            }
            database.resourceDao().update(original)
            assertFalse(store.temporaryCopies().expire(scope, original) { false })
            assertEquals(original, store.resource("a", "space", "cas"))
            assertTrue(store.temporaryCopies().expire(scope, original) { true })
            assertEquals(original.copy(hasLocalCopy = false, localPath = null), store.resource("a", "space", "cas"))
        }

    @Test fun pinsLiteralAncestorsAndActiveDownloadsAreRecheckedAfterPageSelection() =
        runBlocking {
            val original = row("target").copy(path = "/%_root/target")
            database.resourceDao().insert(original)
            val scope = capture()
            val expected = store.temporaryCopies().page(scope).single()
            val parent = row("parent").copy(path = "/%_root", kind = ResourceKind.FOLDER, offlinePinned = true)
            database.resourceDao().insert(parent)
            assertFalse(store.temporaryCopies().expire(scope, expected) { error("Pinned ancestor invoked callback") })
            database.resourceDao().update(parent.copy(path = "/%xroot"))
            val otherAccountPin = parent.copy(accountId = "other")
            database.resourceDao().insert(otherAccountPin)
            for (state in listOf("QUEUED", "RUNNING", "RETRY")) {
                val transfer = download(state)
                database.transferDao().insert(transfer)
                assertFalse(
                    store.temporaryCopies().expire(scope, expected) { error("Active download invoked callback") },
                )
                database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            }
            assertTrue(store.temporaryCopies().expire(scope, expected) { true })
        }

    @Test fun disabledDeletedMissingSpacesAndIncompleteCopiesNeverEnterInventory() =
        runBlocking {
            database.spaceDao().upsertAll(
                listOf(
                    space.copy(driveId = "disabled", isDisabled = true),
                    space.copy(driveId = "deleted", isDeleted = true),
                ),
            )
            val rows =
                listOf(
                    row("valid"),
                    row("disabled").copy(spaceId = "disabled"),
                    row("deleted").copy(spaceId = "deleted"),
                    row("missing").copy(spaceId = "missing"),
                    row("no-copy").copy(hasLocalCopy = false),
                    row("no-path").copy(localPath = null),
                    row("other-account").copy(accountId = "other"),
                )
            database.resourceDao().insertAll(rows)
            assertEquals(listOf(rows.first()), store.temporaryCopies().page(capture()))
        }

    @Test fun accountReplacementAndIdenticalRemoveReaddRejectPagesAndDeletion() =
        runBlocking {
            val original = row("original")
            database.resourceDao().insert(original)
            val replaced = capture()
            database.accountDao().upsert(account.copy(serverUrl = "https://replacement.example.test"))
            assertRejected(replaced, original)
            database.accountDao().upsert(account)
            val removed = capture()
            store.removeAccount("a")
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space))
            database.resourceDao().insert(original)
            assertRejected(removed, original)
            assertEquals(listOf(original), store.temporaryCopies().page(capture()))
            database.accountDao().upsert(account.copy(isActive = false))
            assertNull(store.temporaryCopies().capture("a", directory))
        }

    @Test fun closingOneScopeDoesNotRemoveConcurrentOrUnknownFilesAndClosedScopeCannotDelete() =
        runBlocking {
            val original = row("original")
            database.resourceDao().insert(original)
            val first = capture()
            val second = capture()
            val unknown = File(directory, "unknown-preserved.txt").apply { writeText("preserve") }
            val before = directory.listFiles().orEmpty().toSet()
            first.close()
            first.close()
            assertEquals(before.size - 2, directory.listFiles().orEmpty().size)
            assertTrue(unknown.exists())
            assertRejected(first, original)
            assertEquals(listOf(original), store.temporaryCopies().page(second))
            assertTrue(store.temporaryCopies().expire(second, original) { true })
            second.close()
            assertEquals(setOf(unknown), directory.listFiles().orEmpty().toSet())
        }

    @Test fun cancelledDeletionNeverInvokesCallbackAndInactiveCaptureLeavesNoStage() =
        runBlocking {
            val original = row("original")
            database.resourceDao().insert(original)
            val scope = capture()
            var callbacks = 0
            coroutineScope {
                launch {
                    cancel()
                    store.temporaryCopies().expire(scope, original) {
                        callbacks++
                        true
                    }
                }.join()
            }
            assertEquals(0, callbacks)
            assertEquals(original, store.resource("a", "space", "original"))
            scope.close()
            database.accountDao().upsert(account.copy(isActive = false))
            assertNull(store.temporaryCopies().capture("a", directory))
            assertTrue(directory.listFiles().orEmpty().isEmpty())
        }

    @Test fun cancellingCaptureAfterItsStageExistsClosesAndRemovesOnlyItsOwnDatabase() =
        runBlocking {
            database.resourceDao().insertAll((0 until 400).map { row("id$it") })
            val retained = capture()
            val before = directory.listFiles().orEmpty().toSet()
            val blocker = CaptureBlock()
            captureBlock.set(blocker)
            val capturing = launch(Dispatchers.Default) { store.temporaryCopies().capture("a", directory)?.close() }
            try {
                assertTrue(withContext(Dispatchers.IO) { blocker.started.await(10, TimeUnit.SECONDS) })
                assertTrue(directory.listFiles().orEmpty().size > before.size)
                capturing.cancel()
            } finally {
                captureBlock.set(null)
                blocker.release.countDown()
                withTimeout(10_000) { capturing.join() }
            }
            assertTrue(capturing.isCancelled)
            assertEquals(before, directory.listFiles().orEmpty().toSet())
            assertEquals(128, store.temporaryCopies().page(retained).size)
        }

    private suspend fun capture(): TemporaryCopyScope =
        requireNotNull(store.temporaryCopies().capture("a", directory)).also {
            scopes += it
        }

    private suspend fun assertRejected(
        scope: TemporaryCopyScope,
        original: ResourceEntity,
    ) {
        assertThrows(IOException::class.java) { runBlocking { store.temporaryCopies().page(scope) } }
        assertFalse(store.temporaryCopies().expire(scope, original) { error("Invalid scope invoked callback") })
        assertEquals(original, store.resource("a", "space", original.remoteId))
    }

    private fun ResourceEntity.key() = TemporaryCopyKey(spaceId, remoteId)

    private fun download(state: String) =
        TransferEntity(
            id = "download-$state",
            accountId = "a",
            spaceId = "space",
            resourceId = "target",
            direction = "DOWNLOAD",
            sourceUri = null,
            destinationPath = "/%_root/target",
            displayName = "target",
            mimeType = "text/plain",
            bytesTotal = 4,
            createdAtEpochMillis = 1,
            updatedAtEpochMillis = 1,
            state = state,
        )

    private fun row(id: String) =
        ResourceEntity(
            accountId = "a",
            spaceId = "space",
            remoteId = id,
            parentId = "root",
            path = "/$id",
            name = id,
            kind = ResourceKind.FILE,
            mimeType = "text/plain",
            sizeBytes = 4,
            eTag = "etag",
            modifiedAtEpochMillis = 1,
            createdAtEpochMillis = 2,
            hasLocalCopy = true,
            localPath = "/private/$id",
        )

    private class CaptureBlock {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun awaitCapture(sql: String) {
            if (sql.contains("0 AS keptOffline FROM resources r")) {
                started.countDown()
                check(release.await(15, TimeUnit.SECONDS)) { "Capture fixture timed out" }
            }
        }
    }
}

private fun compareBinary(
    left: String,
    right: String,
): Int {
    val a = left.toByteArray(Charsets.UTF_8)
    val b = right.toByteArray(Charsets.UTF_8)
    for (index in 0 until minOf(a.size, b.size)) {
        val compared = (a[index].toInt() and 255).compareTo(b[index].toInt() and 255)
        if (compared != 0) return compared
    }
    return a.size.compareTo(b.size)
}
