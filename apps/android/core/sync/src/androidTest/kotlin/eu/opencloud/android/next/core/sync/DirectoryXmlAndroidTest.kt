package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Android's SAX implementation differs from the host JVM: verify DTD rejection on device. */
@RunWith(AndroidJUnit4::class)
class DirectoryXmlAndroidTest {
    private val listing =
        """<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/</d:href>
        <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>
        <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"""

    @Test fun nativeParserAcceptsCollectionAndRejectsDoctype() {
        assertEquals(emptyList<Any>(), client(listing).folder("https://example.test/dav/", "/", "Bearer synthetic"))
        val malicious = "<!DOCTYPE d:multistatus [<!ENTITY secret SYSTEM 'file:///does-not-exist'>]>$listing"
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client(malicious).folder("https://example.test/dav/", "/", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
    }

    @Test fun nativeParserPreservesBoundedListingFailure() {
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client(listing, 64).folder("https://example.test/dav/", "/", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
    }

    @Test fun nativeParserPreservesFragmentedCdataValue() {
        val value = "<![CDATA[a]]>".repeat(20_000)
        val child =
            """<d:response><d:href>/dav/file</d:href><d:propstat><d:prop>
            <d:getetag>$value</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status>
            </d:propstat></d:response>"""
        val xml = listing.replace("</d:multistatus>", "$child</d:multistatus>")
        val resource = client(xml).folder("https://example.test/dav/", "/", "Bearer synthetic").single()
        assertEquals("a".repeat(20_000), resource.eTag)
    }

    @Test fun nativeParserBoundsInterleavedTextNodes() {
        val content = "a<d:value/>".repeat(2100)
        val xml = listing.replace("<d:prop>", "<d:prop>$content")
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client(xml).folder("https://example.test/dav/", "/", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
    }

    private fun client(
        xml: String,
        limit: Long = 32L * 1024 * 1024,
    ) = RemoteDiscoveryClient(
        OkHttpClient
            .Builder()
            .addInterceptor { chain ->
                Response
                    .Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(207)
                    .message("Multi-Status")
                    .body(xml.toResponseBody())
                    .build()
            }.build(),
        maxResponseBytes = limit,
    )
}
