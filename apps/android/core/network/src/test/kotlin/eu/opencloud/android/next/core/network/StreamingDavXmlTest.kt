package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class StreamingDavXmlTest {
    @Test fun `fragmented CDATA retains one text node and preserves its value`() {
        val value = "<![CDATA[a]]>".repeat(20_000)
        val xml = envelope("<d:response><d:href>$value</d:href></d:response>")
        var responses = 0
        readDavResponses(xml.byteInputStream(), 32L * 1024 * 1024) { response ->
            responses++
            val href = response.getElementsByTagNameNS("DAV:", "href").item(0)
            assertEquals("a".repeat(20_000), href.textContent)
            assertEquals(1, href.childNodes.length)
        }
        assertEquals(1, responses)
    }

    @Test fun `interleaved text and elements count toward the response node limit`() {
        val xml = envelope("<d:response><d:prop>${"a<d:value/>".repeat(2100)}</d:prop></d:response>")
        var responses = 0
        val failure =
            assertThrows(OpenCloudException::class.java) {
                readDavResponses(xml.byteInputStream(), 32L * 1024 * 1024) { responses++ }
            }
        assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
        assertEquals(0, responses)
    }

    private fun envelope(response: String) = """<d:multistatus xmlns:d="DAV:">$response</d:multistatus>"""
}
