package eu.opencloud.android.next.core.network

import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/** DAV uses HTTP dates; creation dates and some servers use ISO 8601. Zero means unknown. */
internal fun parseRemoteTimestamp(value: String?): Long {
    val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return 0
    return try {
        ZonedDateTime.parse(text, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
    } catch (_: DateTimeParseException) {
        try {
            Instant.parse(text).toEpochMilli()
        } catch (_: DateTimeParseException) {
            0
        }
    }
}
