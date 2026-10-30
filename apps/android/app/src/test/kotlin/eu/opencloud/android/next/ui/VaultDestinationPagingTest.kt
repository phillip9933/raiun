package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.ACCOUNT
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
import java.util.UUID
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultDestinationPagingTest {
    private val fixtures = VaultViewModelRaceTest()

    @After fun resetMain() = Dispatchers.resetMain()

    @Test fun `later destination pages select beyond 128 and reissue source leases`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val source = file("source.txt")
            val children = (0 until 300).map { file("folder${it.toString().padStart(3, '0')}", true) }
            val opened = Session(source, children + file("visible.txt"))
            val model = open(opened)
            advanceUntilIdle()
            val sourceId =
                model.state.value.entries
                    .single()
                    .id
            model.beginDestinationPicker(sourceId, "dest")
            advanceUntilIdle()
            assertEquals(
                301L,
                model.state.value.destinationPickerPage
                    ?.total,
            )
            model.destinationPage(false)
            advanceUntilIdle()
            assertEquals(
                41L,
                model.state.value.destinationPickerPage
                    ?.offset,
            )
            model.destinationPage(true)
            advanceUntilIdle()
            assertEquals(
                0L,
                model.state.value.destinationPickerPage
                    ?.offset,
            )
            while (model.state.value.destinationPickerEntries
                    .none { it.name == "folder190" }
            ) {
                model.destinationPage(false)
                advanceUntilIdle()
            }
            val chosen =
                model.state.value.destinationPickerEntries
                    .first { it.name == "folder190" }
            assertTrue(
                model.state.value.destinationPickerPage!!
                    .offset > 128,
            )
            model.loadDestinationFolders(chosen.path)
            advanceUntilIdle()
            model.onEntryAction(sourceId, VaultEntryAction.COPY, chosen.path)
            model.dismissDestinationPicker()
            advanceUntilIdle()
            assertEquals(1, opened.copyCalls)
            assertEquals(chosen.path, opened.copyDestination)
            assertEquals("", opened.sourceProofPath)
            assertEquals(0, opened.legacyCalls)
            assertNull(model.state.value.destinationPickerPath)
            model.leaveRoute()
            assertTrue(opened.snapshots.all { it.closed })
        }

    @Test fun `conflict candidates are literal case sensitive and rescanned across pages after a race`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val source = file("source.txt")
            val occupied =
                (0 until 300).map { file("item${it.toString().padStart(3, '0')}") } +
                    listOf(file("source.txt"), file("source (1).txt"), file("source (2).txt"), file("Source (3).txt"))
            val opened = Session(source, occupied)
            val model = open(opened)
            advanceUntilIdle()
            val sourceId =
                model.state.value.entries
                    .single()
                    .id
            model.onEntryAction(sourceId, VaultEntryAction.COPY, "dest")
            advanceUntilIdle()
            assertEquals(
                "source (3).txt",
                model.state.value.transferConflict
                    ?.proposedName,
            )
            assertTrue(opened.snapshots.any { it.offsets.any { offset -> offset > 128 } })
            opened.destinations += file("source (3).txt")
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(
                "source (4).txt",
                model.state.value.transferConflict
                    ?.proposedName,
            )
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(1, opened.copyCalls)
            assertEquals("source (4).txt", opened.copiedName)
            assertEquals("", opened.sourceProofPath)
            assertEquals(0, opened.legacyCalls)
            model.leaveRoute()
        }

    @Test fun `source folder exclusion and hidden names affect destination count before paging`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val source = file("aaa-source", true)
            val opened = Session(source, emptyList())
            opened.rootEntries = (0 until 180).map { file("folder$it", true) } + source + file(".hidden", true)
            val model = open(opened)
            advanceUntilIdle()
            model.beginDestinationPicker(
                model.state.value.entries
                    .first { it.path == source.path }
                    .id,
                "",
            )
            advanceUntilIdle()
            assertEquals(
                180L,
                model.state.value.destinationPickerPage
                    ?.total,
            )
            assertTrue(
                model.state.value.destinationPickerEntries
                    .none { it.name == "aaa-source" || it.name == ".hidden" },
            )
            model.setShowHidden(true)
            advanceUntilIdle()
            assertEquals(
                181L,
                model.state.value.destinationPickerPage
                    ?.total,
            )
            assertEquals("aaa-source", opened.exclusions.last())
            model.leaveRoute()
        }

    @Test fun `dismissal closes late destination snapshots and preserves original contents`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<VaultRouteDirectorySnapshot>? = null
            val opened = Session(file("source.txt"), listOf(file("folder", true)))
            opened.delayDestination = { suspendCoroutine { pending = it } }
            val model = open(opened)
            advanceUntilIdle()
            model.beginDestinationPicker(
                model.state.value.entries
                    .single()
                    .id,
                "dest",
            )
            runCurrent()
            val pendingSnapshot = opened.snapshots.last()
            model.dismissDestinationPicker()
            runCurrent()
            requireNotNull(pending).resume(pendingSnapshot)
            advanceUntilIdle()
            assertTrue(pendingSnapshot.closed)
            assertNull(model.state.value.destinationPickerPage)
            assertNull(model.state.value.destinationPickerPath)
            assertEquals(
                "source.txt",
                model.state.value.entries
                    .single()
                    .name,
            )
            model.leaveRoute()
        }

    @Test fun `offline metadata capacity has a specific error and keeps the proven session unlocked`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = Session(file("source.txt"), emptyList())
            val model = open(opened)
            advanceUntilIdle()
            model.keepDirectoryOffline()
            advanceUntilIdle()
            assertEquals(VaultRouteError.OFFLINE_INDEX_FULL, model.state.value.error)
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertFalse(opened.closed)
            model.leaveRoute()
        }

    private suspend fun kotlinx.coroutines.test.TestScope.open(opened: Session): VaultViewModel {
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

    private fun file(
        name: String,
        folder: Boolean = false,
    ) = fixtures.folder(name).copy(isFolder = folder, strongETag = "\"v1\"")

    private class Session(
        private val source: VaultFolder,
        var destinations: List<VaultFolder>,
    ) : VaultRouteSession {
        override val identity = VaultViewModelRaceTest.identity
        val snapshots = mutableListOf<Snapshot>()
        val exclusions = mutableListOf<String?>()
        var legacyCalls = 0
        var copyCalls = 0
        var copiedName: String? = null
        var copyDestination: String? = null
        var sourceProofPath: String? = null
        var closed = false
        var delayDestination: (suspend () -> VaultRouteDirectorySnapshot)? = null
        var rootEntries = listOf(source)
        private var issued = emptyList<VaultFolder>()
        private var issuedPath = ""

        override suspend fun list(path: String): List<VaultFolder> {
            legacyCalls++
            error("Legacy list forbidden")
        }

        override suspend fun openDirectory(
            path: String,
            showHidden: Boolean,
            excludedPath: String?,
        ): VaultRouteDirectorySnapshot {
            snapshots.lastOrNull()?.close()
            exclusions += excludedPath
            val children =
                when (path) {
                    "" -> rootEntries
                    "dest" -> destinations
                    else -> emptyList()
                }
            val snapshot =
                Snapshot(
                    children
                        .filter { showHidden || !it.name.startsWith('.') }
                        .filter {
                            excludedPath == null ||
                                it.path != excludedPath &&
                                !it.path.startsWith(excludedPath + "/")
                        }.sortedWith(
                            compareBy<VaultFolder> { !it.isFolder }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
                        ),
                ) { page ->
                    issued = page
                    issuedPath = path
                }
            snapshots += snapshot
            return if (path == "dest") delayDestination?.invoke() ?: snapshot else snapshot
        }

        override suspend fun copy(
            entry: VaultFolder,
            destinationPath: String,
            newName: String,
        ): VaultFolder {
            check(entry in issued && issuedPath == "") { "Source was not reissued after destination scan" }
            copyCalls++
            copiedName = newName
            copyDestination = destinationPath
            sourceProofPath = issuedPath
            return entry
        }

        override suspend fun pinOfflineDirectory(path: String): Unit =
            throw OpenCloudException(OpenCloudError.EncryptedOfflineIndexFull)

        override suspend fun preview(entry: VaultFolder): ByteArray = error("unused")

        override suspend fun exportVerifiedKeyMaterial() = ByteArray(80)

        override fun close() {
            closed = true
            snapshots.forEach { it.close() }
        }
    }

    private class Snapshot(
        private val rows: List<VaultFolder>,
        private val publish: (List<VaultFolder>) -> Unit,
    ) : VaultRouteDirectorySnapshot {
        val offsets = mutableListOf<Long>()
        var closed = false
        override val totalCount get() = rows.size.toLong()

        override suspend fun page(
            offset: Long,
            limit: Int,
        ): List<VaultFolder> {
            check(!closed)
            offsets += offset
            return rows
                .drop(offset.toInt())
                .take(minOf(limit, 41))
                .map { it.copy(leaseId = UUID.randomUUID().toString()) }
                .also(publish)
        }

        override fun close() {
            closed = true
        }
    }
}
