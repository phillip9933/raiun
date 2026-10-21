package eu.opencloud.android.next.core.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class VaultFilterTest {
    @Test fun `missing vault property in 404 propstat does not hide ordinary files`() {
        assertFalse(response("404 Not Found", "").isEncryptedVault())
        assertFalse(response("200 OK", "").isEncryptedVault())
        assertTrue(response("200 OK", "integrity-token").isEncryptedVault())
    }

    private fun response(
        status: String,
        value: String,
    ): Element =
        parseSafeXml(
            """<d:response xmlns:d="DAV:" xmlns:v="ocrclone"><d:propstat><d:prop>
        <v:integrity-id>$value</v:integrity-id></d:prop><d:status>HTTP/1.1 $status</d:status>
        </d:propstat></d:response>""",
        ).documentElement
}
