package eu.opencloud.android.next

import org.junit.rules.ExternalResource
import java.util.TimeZone

/** Timestamp goldens use a fixed fixture zone rather than the host workstation zone. */
class GoldenTimeZoneRule(
    private val zoneId: String,
) : ExternalResource() {
    private var previous = TimeZone.getDefault()

    override fun before() {
        previous = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone(zoneId))
    }

    override fun after() {
        TimeZone.setDefault(previous)
    }
}
