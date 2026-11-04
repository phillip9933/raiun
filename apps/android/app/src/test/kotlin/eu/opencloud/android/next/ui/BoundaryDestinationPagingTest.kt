package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.BoundaryDestinationFolder
import eu.opencloud.android.next.core.sync.BoundaryDestinationSnapshot
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.BoundaryNameIndex
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.InputStream
import java.io.OutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BoundaryDestinationPagingTest {
    @Test fun shortPagesUseActualOffsetsAndPreviousBookmarksWithoutAccumulatingRows() {
        val fixture = BoundaryDestinationPagingFixture()
        val controller = fixture.controller()
        try {
            controller.select(fixture.first)
            assertEquals(37, controller.state.value.folders.size)
            assertEquals(
                333L,
                controller.state.value.page
                    ?.total,
            )
            controller.page(false)
            assertEquals(
                37L,
                controller.state.value.page
                    ?.offset,
            )
            assertEquals(
                (37L..73L).map { "folder-$it" },
                controller.state.value.folders
                    .map { it.id },
            )
            controller.page(false)
            assertEquals(
                74L,
                controller.state.value.page
                    ?.offset,
            )
            controller.page(true)
            assertEquals(
                37L,
                controller.state.value.page
                    ?.offset,
            )
            controller.page(true)
            assertEquals(
                0L,
                controller.state.value.page
                    ?.offset,
            )
            assertEquals(listOf(0L, 37L, 74L, 37L, 0L), fixture.snapshot.offsets)
            assertEquals(37, controller.state.value.folders.size)
            assertTrue(controller.state.value.targetValidated)
        } finally {
            controller.close()
        }
        assertEquals(1, fixture.snapshot.closes)
    }

    @Test fun aVaultMarkerBeyondFirst128RowsMapsTheAdmittedRootIntoUnlock() {
        val fixture = BoundaryDestinationPagingFixture(chunk = 128, marker = 260)
        val controller = fixture.controller()
        try {
            controller.select(fixture.first)
            controller.page(false)
            controller.page(false)
            val selected =
                controller.state.value.folders
                    .single { it.isVaultRoot }
            controller.open(selected)
            val unlock = requireNotNull(controller.state.value.unlock)
            assertEquals(VaultLocationKind.FOLDER_VAULT, unlock.kind)
            assertEquals("vault-root", unlock.remoteVaultId)
            assertEquals("Secret", unlock.vaultPath)
            assertEquals(fixture.first.driveId, unlock.driveId)
            assertEquals(1, fixture.snapshot.closes)
            val password = "synthetic".toCharArray()
            controller.unlock(password)
            assertEquals(listOf(unlock), fixture.unlockedLocations)
            assertTrue(password.all { it == '\u0000' })
            assertTrue(controller.state.value.targetValidated)
        } finally {
            controller.close()
        }
        assertEquals(1, fixture.unlockCloses)
    }

    @Test fun aFailedNewRootCannotReuseRowsOrPlaceIntoTheLastSuccessfulRoot() {
        val fixture = BoundaryDestinationPagingFixture(failSecond = true)
        val controller = fixture.controller()
        try {
            controller.select(fixture.first)
            assertTrue(controller.state.value.targetValidated)
            controller.select(fixture.second)
            assertEquals(fixture.second, controller.state.value.location)
            assertEquals(OpenCloudError.AccessDenied, controller.state.value.error)
            assertFalse(controller.state.value.targetValidated)
            assertTrue(
                controller.state.value.folders
                    .isEmpty(),
            )
            assertNull(controller.state.value.page)
            controller.transfer()
            assertEquals(0, fixture.nameCaptures)
            controller.up()
            assertNull(controller.state.value.location)
            assertEquals(listOf(fixture.first, fixture.second), controller.state.value.locations)
        } finally {
            controller.close()
        }
    }
}

internal class BoundaryDestinationPagingFixture(
    total: Long = 333,
    chunk: Int = 37,
    marker: Long? = null,
    private val failSecond: Boolean = false,
) {
    val first = location("first")
    val second = location("second")
    val snapshot = Snapshot(total, chunk, marker)
    val unlockedLocations = mutableListOf<VaultLocation>()
    var unlockCloses = 0
    var nameCaptures = 0
    private val source = Endpoint { Snapshot(0, 128, null) }
    val request =
        BoundaryTransferRequest(
            "account",
            false,
            unlocked = source to BoundaryEntry("source", "file.txt", "file.txt", false, 1, "\"1\""),
        )

    fun controller(): BoundaryDestinationController {
        val repository =
            object : BoundaryDestinationRepository {
                override suspend fun locations(accountId: String) = listOf(first, second)

                override suspend fun ordinaryEndpoint(
                    accountId: String,
                    location: VaultLocation,
                ): BoundaryEndpoint =
                    Endpoint {
                        if (failSecond && location == second) throw OpenCloudException(OpenCloudError.AccessDenied)
                        snapshot
                    }

                override suspend fun folders(
                    accountId: String,
                    location: VaultLocation,
                    path: String,
                ): List<VaultFolder> = error("The chooser must not request a complete legacy folder list")

                override suspend fun unlock(
                    accountId: String,
                    location: VaultLocation,
                    password: CharArray,
                ): BoundaryUnlockedDestination {
                    unlockedLocations += location
                    return BoundaryUnlockedDestination(Endpoint { Snapshot(0, 128, null) }) { unlockCloses++ }
                }
            }
        return BoundaryDestinationController(
            ApplicationProvider.getApplicationContext<Context>(),
            request,
            repository,
            Dispatchers.Unconfined,
            Dispatchers.Unconfined,
        )
    }

    inner class Endpoint(
        private val open: () -> BoundaryDestinationSnapshot,
    ) : BoundaryEndpoint {
        override val identity = "fixture-${System.identityHashCode(this)}"
        override val encrypted = false

        override suspend fun openDestinationFolders(
            context: Context,
            path: String,
        ) = open()

        override suspend fun list(path: String): List<BoundaryEntry> = error("Legacy list is forbidden")

        override suspend fun openNameIndex(
            context: Context,
            path: String,
        ): BoundaryNameIndex {
            nameCaptures++
            error("Unexpected transfer preflight")
        }

        override suspend fun requireUnchanged(entry: BoundaryEntry) = Unit

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ): Unit = error("Unexpected read")

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry = error("Unexpected write")

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry = error("Unexpected mkdir")

        override suspend fun delete(entry: BoundaryEntry): Unit = error("Unexpected delete")
    }

    class Snapshot(
        override val totalCount: Long,
        private val chunk: Int,
        private val marker: Long?,
    ) : BoundaryDestinationSnapshot {
        val offsets = mutableListOf<Long>()
        var closes = 0

        override suspend fun page(
            offset: Long,
            limit: Int,
        ): List<BoundaryDestinationFolder> {
            check(closes == 0)
            offsets += offset
            val count = minOf(chunk.toLong(), limit.toLong(), totalCount - offset).toInt()
            return List(count) { step ->
                val index = offset + step
                if (index == marker) {
                    BoundaryDestinationFolder("vault-root", "Secret", "Secret", true)
                } else {
                    BoundaryDestinationFolder("folder-$index", "folder-$index", "folder-$index", false)
                }
            }
        }

        override fun close() {
            if (closes == 0) closes++
        }
    }

    private fun location(id: String) =
        VaultLocation(
            "account",
            id,
            VaultLocationKind.SPACE,
            id,
            id,
            id,
            "https://example.test",
            "https://example.test/dav/$id",
            "",
            false,
        )
}
