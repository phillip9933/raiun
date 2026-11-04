package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.ACCOUNT
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.identity
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultDirectoryPagingViewModelTest {
    private val fixtures = VaultViewModelRaceTest()

    @After fun resetMain() = Dispatchers.resetMain()

    @Test fun `more than 128 entries traverse complete pages and Previous uses actual short page bookmarks`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = SnapshotSession(rows(301), pageCap = 37)
            val model = open(opened)
            advanceUntilIdle()
            val seen = mutableListOf<String>()
            do {
                val state = model.state.value
                seen += state.entries.map { it.name }
                assertEquals(301L, state.directoryPage?.total)
                assertTrue(state.entries.size <= 37)
                if (state.directoryPage?.hasNext != true) break
                model.directoryPage(false)
                advanceUntilIdle()
            } while (true)
            assertEquals(rows(301).map { it.name }, seen)
            assertEquals(301, seen.toSet().size)
            assertEquals(
                296L,
                model.state.value.directoryPage
                    ?.offset,
            )
            model.directoryPage(true)
            advanceUntilIdle()
            assertEquals(
                259L,
                model.state.value.directoryPage
                    ?.offset,
            )
            model.directoryPage(true)
            advanceUntilIdle()
            assertEquals(
                222L,
                model.state.value.directoryPage
                    ?.offset,
            )
            assertEquals(1, opened.exports)
            assertEquals(1, opened.snapshots.size)
            model.leaveRoute()
            assertTrue(opened.snapshots.single().closed)
        }

    @Test fun `hidden rows filter before count and pages and visibility changes replace snapshot`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = SnapshotSession(rows(150, hidden = true) + rows(15))
            val model = open(opened)
            advanceUntilIdle()
            assertEquals(
                15L,
                model.state.value.directoryPage
                    ?.total,
            )
            assertEquals(15, model.state.value.entries.size)
            assertTrue(
                model.state.value.entries
                    .none { it.name.startsWith('.') },
            )
            assertFalse(
                model.state.value.directoryPage!!
                    .hasNext,
            )
            model.setShowHidden(true)
            advanceUntilIdle()
            assertTrue(opened.snapshots.first().closed)
            assertEquals(
                165L,
                model.state.value.directoryPage
                    ?.total,
            )
            assertEquals(128, model.state.value.entries.size)
            assertTrue(
                model.state.value.entries
                    .all { it.name.startsWith('.') },
            )
            assertEquals(1, opened.exports)
            model.lock()
            assertTrue(opened.snapshots.all { it.closed })
            assertNull(model.state.value.directoryPage)
            model.leaveRoute()
        }

    @Test fun `old page actions are absent after next page and refresh closes previous generation`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = SnapshotSession(rows(300))
            val model = open(opened)
            advanceUntilIdle()
            val oldId =
                model.state.value.entries
                    .first()
                    .id
            model.directoryPage(false)
            advanceUntilIdle()
            model.openPreview(oldId)
            advanceUntilIdle()
            assertEquals(0, opened.previews)
            assertNull(model.state.value.preview)
            model.retry()
            advanceUntilIdle()
            assertTrue(opened.snapshots.first().closed)
            assertEquals(
                0L,
                model.state.value.directoryPage
                    ?.offset,
            )
            assertEquals(
                "file000",
                model.state.value.entries
                    .first()
                    .name,
            )
            assertEquals(1, opened.exports)
            model.leaveRoute()
        }

    @Test fun `late directory returned after lock is closed without publishing entries or exporting key material`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<VaultRouteDirectorySnapshot>? = null
            val opened = SnapshotSession(rows(300), delayDirectory = { suspendCoroutine { pending = it } })
            val model = open(opened)
            runCurrent()
            assertTrue(model.state.value.loading)
            model.lock()
            requireNotNull(pending).resume(opened.snapshots.single())
            advanceUntilIdle()
            assertTrue(opened.closed)
            assertTrue(opened.snapshots.single().closed)
            assertTrue(
                model.state.value.entries
                    .isEmpty(),
            )
            assertNull(model.state.value.directoryPage)
            assertEquals(0, opened.exports)
            model.leaveRoute()
        }

    @Test fun `late page completion cannot mix an old directory with a refreshed generation`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<List<VaultFolder>>? = null
            val opened =
                SnapshotSession(rows(300), delayedPage = { offset, entries ->
                    if (offset == 128L) suspendCoroutine { pending = it } else entries
                })
            val model = open(opened)
            advanceUntilIdle()
            model.directoryPage(false)
            runCurrent()
            assertTrue(model.state.value.loading)
            model.retry()
            runCurrent()
            assertTrue(opened.snapshots.first().closed)
            requireNotNull(pending).resume(rows(300).drop(128).take(128))
            advanceUntilIdle()
            assertEquals(
                0L,
                model.state.value.directoryPage
                    ?.offset,
            )
            assertEquals(
                "file000",
                model.state.value.entries
                    .first()
                    .name,
            )
            assertTrue(
                model.state.value.entries
                    .none { it.name == "file128" },
            )
            model.leaveRoute()
        }

    private suspend fun kotlinx.coroutines.test.TestScope.open(opened: SnapshotSession): VaultViewModel {
        val model = fixtures.newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
        model.enterRoute(ACCOUNT)
        runCurrent()
        model.selectLocation(
            model.state.value.locations
                .single()
                .id,
        )
        model.unlock("secret".toCharArray())
        return model
    }

    private fun rows(
        count: Int,
        hidden: Boolean = false,
    ) = (0 until count).map { n ->
        fixtures.folder("${if (hidden) "." else ""}file${n.toString().padStart(3, '0')}")
    }

    private class SnapshotSession(
        private val rows: List<VaultFolder>,
        private val pageCap: Int = 128,
        private val delayDirectory: (suspend () -> VaultRouteDirectorySnapshot)? = null,
        private val delayedPage: suspend (Long, List<VaultFolder>) -> List<VaultFolder> = { _, entries -> entries },
    ) : VaultRouteSession {
        override val identity = VaultViewModelRaceTest.identity
        val snapshots = mutableListOf<Snapshot>()
        var closed = false
        var exports = 0
        var previews = 0

        override suspend fun list(path: String): List<VaultFolder> = error("Full-list browsing is forbidden")

        override suspend fun openDirectory(
            path: String,
            showHidden: Boolean,
            excludedPath: String?,
        ): VaultRouteDirectorySnapshot {
            snapshots.lastOrNull()?.close()
            val snapshot =
                Snapshot(
                    rows
                        .filter { showHidden || !it.name.startsWith('.') }
                        .filter {
                            excludedPath == null || it.path != excludedPath && !it.path.startsWith(excludedPath + "/")
                        }.sortedBy { it.name },
                    pageCap,
                    delayedPage,
                )
            snapshots += snapshot
            return delayDirectory?.invoke() ?: snapshot
        }

        override suspend fun preview(entry: VaultFolder): ByteArray {
            previews++
            return "preview".toByteArray()
        }

        override suspend fun exportVerifiedKeyMaterial(): ByteArray {
            exports++
            return ByteArray(80)
        }

        override fun close() {
            closed = true
            snapshots.forEach { it.close() }
        }
    }

    private class Snapshot(
        private val rows: List<VaultFolder>,
        private val pageCap: Int,
        private val delayedPage: suspend (Long, List<VaultFolder>) -> List<VaultFolder>,
    ) : VaultRouteDirectorySnapshot {
        var closed = false
        override val totalCount get() = rows.size.toLong()

        override suspend fun page(
            offset: Long,
            limit: Int,
        ): List<VaultFolder> {
            check(!closed)
            return delayedPage(offset, rows.drop(offset.toInt()).take(minOf(limit, pageCap)))
        }

        override fun close() {
            closed = true
        }
    }
}
