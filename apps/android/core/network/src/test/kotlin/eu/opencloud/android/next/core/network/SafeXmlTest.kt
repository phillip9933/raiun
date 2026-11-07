package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class SafeXmlTest {
    @Test fun `DAV namespaces and escaped names survive parsing`() {
        val doc =
            parseSafeXml("""<d:multistatus xmlns:d="DAV:"><d:displayname>A &amp; B</d:displayname></d:multistatus>""")
        assertEquals("A & B", doc.getElementsByTagNameNS("DAV:", "displayname").item(0).textContent)
    }

    @Test fun `only standard and numeric entity references are accepted`() {
        val doc = parseSafeXml("<r>&amp;&lt;&gt;&apos;&quot;&#65;&#x1F600;</r>")
        assertEquals("&<>'\"A😀", doc.documentElement.textContent)
        val literal = parseSafeXml("<r><![CDATA[&unknown;]]><!-- &unknown; --></r>")
        assertEquals("&unknown;", literal.documentElement.textContent)

        val error = assertThrows(OpenCloudException::class.java) { parseSafeXml("<r>&unknown;</r>") }
        assertEquals(OpenCloudError.InvalidResponse, error.error)
        assertEquals("The server returned incomplete or unexpected metadata.", error.message)
        assertNull(error.cause)
    }

    @Test fun `decoded character input does not reinterpret an encoding declaration`() {
        listOf("UTF-8", "UTF-16", "ISO-8859-1").forEach { encoding ->
            val doc =
                parseSafeXml(
                    """<?xml version="1.0" encoding="$encoding"?><r xmlns="DAV:"><displayname>日本語 &amp; café 😀</displayname></r>""",
                )
            assertEquals("日本語 & café 😀", doc.getElementsByTagNameNS("DAV:", "displayname").item(0).textContent)
        }
    }

    @Test fun `untrusted declarations and malformed documents fail without exposing content`() {
        listOf(
            "<!DOCTYPE x SYSTEM 'https://secret.example'><x/>",
            "<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///secret'>]><x>&secret;</x>",
            "<!DOCTYPE x [<!ENTITY a 'expanded'><!ENTITY b '&a;&a;'>]><x>&b;</x>",
            "<!ENTITY secret SYSTEM 'https://secret.example'><x/>",
            "<?xml version='1.0' encoding='UTF-16'?><!DOCTYPE x SYSTEM 'https://secret.example'><x/>",
            "<?xml version='1.0' encoding='ISO-8859-1'?><!DOCTYPE x [<!ENTITY a 'expanded'>]><x>&a;</x>",
            "<x>&unknown;</x>",
            "<x>private",
            "<x>\u0000</x>",
        ).forEach { xml ->
            val error = assertThrows(OpenCloudException::class.java) { parseSafeXml(xml) }
            assertEquals(OpenCloudError.InvalidResponse, error.error)
        }
    }
}
