package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Instant

class RemoteTimestampTest {
    @Test fun acceptsWebDavHttpDateAndIsoDate() {
        val expected = Instant.parse("2026-09-29T12:34:56Z").toEpochMilli()
        assertEquals(expected, parseRemoteTimestamp("Tue, 29 Sep 2026 12:34:56 GMT"))
        assertEquals(expected, parseRemoteTimestamp("2026-09-29T12:34:56Z"))
        assertEquals(expected, parseRemoteTimestamp("2026-09-29T14:34:56+02:00"))
    }

    @Test fun missingMalformedDatesStayUnknown() {
        listOf(null, "", "not a date", "0").forEach { assertEquals(0, parseRemoteTimestamp(it)) }
    }
}
