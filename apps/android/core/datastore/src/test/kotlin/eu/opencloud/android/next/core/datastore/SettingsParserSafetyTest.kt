package eu.opencloud.android.next.core.datastore

import com.google.protobuf.InvalidProtocolBufferException
import eu.opencloud.android.next.core.datastore.proto.AppSettings
import org.junit.Assert.assertThrows
import org.junit.Test

class SettingsParserSafetyTest {
    @Test fun `deeply nested unknown fields are rejected without overflowing the stack`() {
        // Unknown group fields previously bypassed the Java Lite recursion limit (CVE-2024-7254).
        val message = ByteArray(512) { 0x0b.toByte() } + ByteArray(512) { 0x0c.toByte() }
        assertThrows(InvalidProtocolBufferException::class.java) { AppSettings.parseFrom(message) }
    }
}
