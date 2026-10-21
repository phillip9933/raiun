package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SafeXmlTest {
    @Test fun `DAV namespaces and escaped names survive parsing`() {
        val doc =
            parseSafeXml("""<d:multistatus xmlns:d="DAV:"><d:displayname>A &amp; B</d:displayname></d:multistatus>""")
        assertEquals("A & B", doc.getElementsByTagNameNS("DAV:", "displayname").item(0).textContent)
    }

    @Test fun `untrusted declarations and malformed documents fail without exposing content`() {
        listOf(
            "<!DOCTYPE x SYSTEM 'https://secret.example'><x/>",
            "<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///secret'>]><x>&secret;</x>",
            "<x>private",
            "<x>\u0000</x>",
        ).forEach { xml ->
            val error = assertThrows(OpenCloudException::class.java) { parseSafeXml(xml) }
            assertEquals(OpenCloudError.InvalidResponse, error.error)
        }
    }
}
