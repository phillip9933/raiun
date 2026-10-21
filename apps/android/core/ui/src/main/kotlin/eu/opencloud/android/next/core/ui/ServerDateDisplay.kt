package eu.opencloud.android.next.core.ui

import java.text.DateFormat
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Date

fun displayServerDate(value: String): String =
    try {
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date.from(Instant.parse(value)))
    } catch (_: DateTimeParseException) {
        value
    }
