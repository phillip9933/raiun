package eu.opencloud.android.next.feature.transfers

import eu.opencloud.android.next.core.database.TransferEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.time.ZoneId

class TransferFiltersTest {
    private val zone = ZoneId.of("America/New_York")

    @Test fun `filters combine direction status type and started date`() {
        val filter =
            TransferFilters(
                direction = "DOWNLOAD",
                status = TransferStatusFilter.ATTENTION,
                fileType = TransferFileType.DOCUMENTS,
                startDate = LocalDate.of(2026, 3, 8),
                endDate = LocalDate.of(2026, 3, 8),
            )
        val target = transfer().copy(direction = "DOWNLOAD", state = "CONFLICT", displayName = "Report.PDF")
        assertTrue(filter.matches(target, zone))
        assertFalse(filter.matches(target.copy(direction = "UPLOAD"), zone))
        assertFalse(filter.matches(target.copy(state = "SUCCEEDED"), zone))
        assertFalse(filter.matches(target.copy(displayName = "song.mp3"), zone))
    }

    @Test fun `range includes entire local day across daylight saving transition`() {
        val date = LocalDate.of(2026, 3, 8)
        val filter = TransferFilters(startDate = date, endDate = date)
        val start = date.atStartOfDay(zone).toInstant().toEpochMilli()
        val end =
            date
                .plusDays(1)
                .atStartOfDay(zone)
                .toInstant()
                .toEpochMilli()
        assertTrue(filter.matches(transfer().copy(createdAtEpochMillis = start), zone))
        assertTrue(filter.matches(transfer().copy(createdAtEpochMillis = end - 1), zone))
        assertFalse(filter.matches(transfer().copy(createdAtEpochMillis = start - 1), zone))
        assertFalse(filter.matches(transfer().copy(createdAtEpochMillis = end), zone))
    }

    @Test fun `range uses started date rather than update date`() {
        val filter = TransferFilters(startDate = LocalDate.of(2026, 3, 9))
        assertFalse(filter.matches(transfer().copy(updatedAtEpochMillis = Long.MAX_VALUE), zone))
    }

    @Test fun `active includes retries and locked vault downloads`() {
        val filter = TransferFilters(status = TransferStatusFilter.ACTIVE)
        listOf("QUEUED", "RUNNING", "RETRY", "AWAITING_UNLOCK").forEach {
            assertTrue(filter.matches(transfer().copy(state = it), zone))
        }
        assertFalse(filter.matches(transfer().copy(state = "FAILED"), zone))
    }

    @Test fun `file type recognizes MIME and missing or generic MIME extension fallback`() {
        assertEquals(
            TransferFileType.IMAGES,
            transferFileType(transfer().copy(mimeType = "image/jpeg", displayName = "no extension")),
        )
        assertEquals(
            TransferFileType.VIDEOS,
            transferFileType(transfer().copy(mimeType = "application/octet-stream", displayName = "Clip.MOV")),
        )
        assertEquals(
            TransferFileType.DOCUMENTS,
            transferFileType(transfer().copy(mimeType = "application/pdf; charset=binary")),
        )
        assertEquals(TransferFileType.AUDIO, transferFileType(transfer().copy(displayName = "sound.FLAC")))
        assertEquals(TransferFileType.OTHER, transferFileType(transfer().copy(displayName = "archive.zip")))
    }

    @Test fun `filtering preserves original data and section placement`() {
        val upload = transfer()
        val download = transfer().copy(id = "download", direction = "DOWNLOAD", state = "SUCCEEDED")
        val state = categorizeTransfers(listOf(upload, download)).copy(spaceNames = mapOf("space" to "Personal"))
        val result = state.filtered(TransferFilters(direction = "DOWNLOAD"), zone)
        assertEquals(emptyList<TransferEntity>(), result.active)
        assertEquals(listOf(download), result.history)
        assertEquals(state.spaceNames, result.spaceNames)
        assertEquals(listOf(upload), state.active)
    }

    private fun transfer() =
        TransferEntity(
            "transfer",
            "account",
            "space",
            null,
            "UPLOAD",
            null,
            "/file",
            "file",
            null,
            10,
            createdAtEpochMillis =
                LocalDate
                    .of(2026, 3, 8)
                    .atStartOfDay(zone)
                    .toInstant()
                    .toEpochMilli(),
            updatedAtEpochMillis = 0,
        )
}
