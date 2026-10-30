package eu.opencloud.android.next.feature.transfers

import androidx.room.Room
import androidx.room.withTransaction
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferInventory
import eu.opencloud.android.next.core.database.TransferInventoryFileType
import eu.opencloud.android.next.core.database.TransferInventoryFilter
import eu.opencloud.android.next.core.database.TransferInventoryStatus
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

@RunWith(RobolectricTestRunner::class)
class TransferInventoryOracleTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var inventory: TransferInventory

    @Before fun setUp() =
        runBlocking {
            database =
                Room
                    .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                    .allowMainThreadQueries()
                    .build()
            inventory = TransferInventory(database)
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "user", "User", "BASIC", false))
            database.accountDao().upsert(
                AccountEntity("other", "https://example.test", "other", "Other", "BASIC", false),
            )
        }

    @After fun close() = database.close()

    @Test fun allFilterCategoriesMatchExistingKotlinOracleAcrossCompleteOrderedWindows() =
        runBlocking {
            val samples =
                listOf(
                    "photo.JPG" to null,
                    "clip.MKV" to null,
                    "song.MP3" to null,
                    "paper.PDF" to null,
                    "unknown.bin" to null,
                    "file" to null,
                    ".jpg" to null,
                    "ending." to null,
                    "image.txt" to " IMAGE/PNG ; q=1",
                    "video.jpg" to "video/mp4",
                    "text.mp4" to "text/plain; charset=utf-8",
                    "opaque" to "application/vnd.oasis.opendocument.text",
                    "日本語.docx" to "",
                    "音楽.bin" to " AuDiO/FlAc ",
                    "odd.jpg" to "İMAGE/JPEG",
                )
            val states =
                listOf("QUEUED", "RUNNING", "RETRY", "AWAITING_UNLOCK", "FAILED", "CONFLICT", "SUCCEEDED", "CANCELLED")
            val rows =
                buildList {
                    for (state in states) {
                        for (direction in listOf("UPLOAD", "DOWNLOAD")) {
                            for ((name, mime) in samples) {
                                add(row(size, state, direction, name, mime, 1_800_000_000_000L + size % 3))
                            }
                        }
                    }
                }
            database.withTransaction {
                rows.forEach { database.transferDao().insert(it) }
                rows
                    .take(
                        8,
                    ).forEach { database.transferDao().insert(it.copy(id = "other-${it.id}", accountId = "other")) }
            }
            val zone = ZoneId.of("UTC")
            for (status in TransferStatusFilter.entries) {
                for (type in TransferFileType.entries) {
                    for (direction in listOf(null, "UPLOAD", "DOWNLOAD")) {
                        val oracle = TransferFilters(direction = direction, status = status, fileType = type)
                        val filter =
                            TransferInventoryFilter(
                                direction = direction,
                                status = TransferInventoryStatus.entries.single { it.name.equals(status.name, true) },
                                fileType = TransferInventoryFileType.entries.single { it.name.equals(type.name, true) },
                            )
                        assertCompleteWindows(rows.filter { oracle.matches(it, zone) }, filter)
                    }
                }
            }
        }

    @Test fun dateWindowsUseLocalDayBoundariesAcrossSpringAndAutumnDst() =
        runBlocking {
            val rows = mutableListOf<TransferEntity>()
            val zones = listOf("America/New_York", "UTC", "Asia/Tokyo").map(ZoneId::of)
            val dates = listOf(LocalDate.of(2026, 3, 8), LocalDate.of(2026, 11, 1))
            for (zone in zones) {
                for (date in dates) {
                    val start = date.atStartOfDay(zone).toInstant().toEpochMilli()
                    val end =
                        date
                            .plusDays(1)
                            .atStartOfDay(zone)
                            .toInstant()
                            .toEpochMilli()
                    for (time in listOf(start - 1, start, start + 90 * 60_000, end - 1, end)) {
                        rows += row(rows.size, "SUCCEEDED", "DOWNLOAD", "day.pdf", null, time)
                    }
                }
            }
            for (time in listOf("2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z")) {
                rows += row(rows.size, "SUCCEEDED", "DOWNLOAD", "repeat.pdf", null, Instant.parse(time).toEpochMilli())
            }
            database.withTransaction { rows.forEach { database.transferDao().insert(it) } }
            for (zone in zones) {
                for (date in dates) {
                    for ((first, last) in listOf(date to date, null to date, date to null)) {
                        val oracle = TransferFilters(startDate = first, endDate = last)
                        val filter =
                            TransferInventoryFilter(
                                startEpochMillisInclusive = first?.atStartOfDay(zone)?.toInstant()?.toEpochMilli(),
                                endEpochMillisExclusive =
                                    last
                                        ?.plusDays(1)
                                        ?.atStartOfDay(zone)
                                        ?.toInstant()
                                        ?.toEpochMilli(),
                            )
                        assertCompleteWindows(rows.filter { oracle.matches(it, zone) }, filter)
                    }
                }
            }
            assertCompleteWindows(emptyList(), TransferInventoryFilter(matchNone = true))
        }

    private suspend fun assertCompleteWindows(
        expected: List<TransferEntity>,
        filter: TransferInventoryFilter,
    ) {
        val ordered =
            expected.sortedWith(
                compareBy<TransferEntity> { bucket(it.state) }
                    .thenByDescending { it.createdAtEpochMillis }
                    .thenByDescending { it.id },
            )
        val actual = mutableListOf<TransferEntity>()
        var offset = 0
        do {
            val page = inventory.load("a", filter, offset)
            assertTrue(page.accessible)
            assertEquals(ordered.size, page.total)
            assertEquals(expected.count { bucket(it.state) == 0 }, page.counts.active)
            assertEquals(expected.count { bucket(it.state) == 1 }, page.counts.attention)
            assertEquals(expected.count { bucket(it.state) == 2 }, page.counts.history)
            assertTrue(page.entries.size <= 128)
            actual += page.entries
            if (!page.hasNext) break
            assertTrue(page.entries.isNotEmpty())
            offset = page.offset + page.entries.size
        } while (true)
        assertEquals(ordered.map { it.id }, actual.map { it.id })
    }

    private fun bucket(state: String): Int =
        when (state) {
            "QUEUED", "RUNNING", "RETRY", "AWAITING_UNLOCK" -> 0
            "FAILED", "CONFLICT" -> 1
            else -> 2
        }

    @Suppress("LongParameterList") // Keep the independent direction/state/type/date fixture axes explicit.
    private fun row(
        index: Int,
        state: String,
        direction: String,
        name: String,
        mime: String?,
        created: Long,
    ) = TransferEntity(
        id = index.toString().padStart(6, '0'),
        accountId = "a",
        spaceId = "space",
        resourceId = null,
        direction = direction,
        sourceUri = null,
        destinationPath = "/$index",
        displayName = name,
        mimeType = mime,
        bytesTotal = 16,
        state = state,
        createdAtEpochMillis = created,
        updatedAtEpochMillis = created,
    )
}
