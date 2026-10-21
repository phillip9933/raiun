package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DavPropertiesTest {
    @Test fun `properties split across successful propstats are combined`() {
        assertEquals(
            DavObject(false, 3, "\"v1\""),
            parseDavObject(xml("/dav/a%2bb.jpg"), "https://cloud.example/dav/a+b.jpg"),
        )
    }

    @Test fun `different paths origins encoded separators and duplicate properties are rejected`() {
        listOf("/dav/other.jpg", "https://other.example/dav/a+b.jpg", "/dav/a%2Fb.jpg", "/dav/a+b.jpg?x=1")
            .forEach { href ->
                assertThrows(
                    OpenCloudException::class.java,
                ) { parseDavObject(xml(href), "https://cloud.example/dav/a+b.jpg") }
            }
        assertThrows(OpenCloudException::class.java) {
            parseDavObject(
                xml("/dav/a+b.jpg").replace(
                    "<d:getcontentlength>3</d:getcontentlength>",
                    "<d:getcontentlength>3</d:getcontentlength><d:getcontentlength>4</d:getcontentlength>",
                ),
                "https://cloud.example/dav/a+b.jpg",
            )
        }
    }

    private fun xml(href: String) =
        """
        <d:multistatus xmlns:d="DAV:"><d:response><d:href>$href</d:href>
        <d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
        <d:propstat><d:prop><d:getcontentlength>3</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop>
        <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>
        """.trimIndent()
}
