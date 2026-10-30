package eu.opencloud.android.next.feature.transfers

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

class TransferInventoryFilterMappingTest {
    @Test fun localDatesBecomeEquivalentEpochPredicatesAtDstAndEpochExtremes() {
        for (zone in listOf("America/New_York", "UTC", "Asia/Tokyo").map(ZoneId::of)) {
            val firstDate = Instant.ofEpochMilli(Long.MIN_VALUE).atZone(zone).toLocalDate()
            val lastDate = Instant.ofEpochMilli(Long.MAX_VALUE).atZone(zone).toLocalDate()
            val dates = listOf(LocalDate.of(2026, 3, 8), LocalDate.of(2026, 11, 1), firstDate, lastDate)
            val times = mutableSetOf(Long.MIN_VALUE, Long.MAX_VALUE, 0L)
            for (date in dates.take(2)) {
                val start = date.atStartOfDay(zone).toInstant().toEpochMilli()
                val end =
                    date
                        .plusDays(1)
                        .atStartOfDay(zone)
                        .toInstant()
                        .toEpochMilli()
                times += listOf(start - 1, start, end - 1, end)
            }
            for (date in dates + LocalDate.MIN + LocalDate.MAX) {
                for ((start, end) in listOf(date to date, null to date, date to null)) {
                    assertMapping(zone, start, end, times)
                }
            }
        }
    }

    private fun assertMapping(
        zone: ZoneId,
        start: LocalDate?,
        end: LocalDate?,
        times: Set<Long>,
    ) {
        val mapped = TransferFilters(startDate = start, endDate = end).inventoryFilter(zone)
        val lower = mapped.startEpochMillisInclusive
        val upper = mapped.endEpochMillisExclusive
        for (time in times) {
            val day = Instant.ofEpochMilli(time).atZone(zone).toLocalDate()
            val oracle = (start == null || day >= start) && (end == null || day <= end)
            val lowerMatches = lower == null || time >= lower
            val upperMatches = upper == null || time < upper
            assertEquals("$zone $start $end $time", oracle, !mapped.matchNone && lowerMatches && upperMatches)
        }
    }
}
