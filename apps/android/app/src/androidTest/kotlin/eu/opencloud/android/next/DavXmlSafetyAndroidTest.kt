package eu.opencloud.android.next

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.network.FileVersionsClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.WebDavFeatureClient
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Runs the device DOM implementation through public clients; the interceptor performs no network IO. */
@RunWith(AndroidJUnit4::class)
class DavXmlSafetyAndroidTest {
    @Test fun trashAndVersionsRejectUnsafeXmlWithControlledErrors() {
        val external =
            "<!DOCTYPE x [<!ENTITY private SYSTEM 'file:///raiun-synthetic-missing-entity'>]>" +
                "<x>&private;</x>"
        val unsafe =
            listOf(
                external,
                "<!DOCTYPE x SYSTEM 'file:///raiun-synthetic-missing-dtd'><x/>",
                "<!DOCTYPE x [<!ENTITY a 'expanded'><!ENTITY b '&a;&a;'>]><x>&b;</x>",
                "<!ENTITY a 'expanded'><x/>",
                "<x>\u0000</x>",
                "<x>private",
                "<x>&unknown;</x>",
                "<?xml version='1.0' encoding='UTF-16'?>$external",
                "<?xml version='1.0' encoding='ISO-8859-1'?>$external",
            )
        unsafe.forEachIndexed { index, xml ->
            listOf(Charsets.UTF_8, Charsets.UTF_16, Charsets.ISO_8859_1).forEach { charset ->
                val http = fixtureClient(xml.toByteArray(charset), charset.name())
                val fixture = "fixture=${index + 1}, charset=${charset.name()}"
                assertInvalid("$fixture, client=trash") {
                    WebDavFeatureClient(http).trash(ROOT, "space", "Bearer synthetic")
                }
                assertInvalid("$fixture, client=versions") {
                    FileVersionsClient(http).list(ROOT, "file", "Bearer synthetic")
                }
            }
        }
    }

    @Test fun trashKeepsNamespacesEscapedUnicodeAndLegalAlternateEncoding() {
        val xml =
            """<?xml version="1.0"?><multistatus xmlns="DAV:" xmlns:t="http://owncloud.org/ns"><response><href>/remote.php/dav/spaces/trash-bin/space/item</href><propstat><prop><t:trashbin-original-filename>日本語 &amp; café 😀.txt</t:trashbin-original-filename><t:trashbin-original-location>Docs/A &amp; B.txt</t:trashbin-original-location><getcontentlength>12</getcontentlength><resourcetype/></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"""
        listOf(Charsets.UTF_8, Charsets.UTF_16).forEach { charset ->
            val client = WebDavFeatureClient(fixtureClient(xml.toByteArray(charset), charset.name()))
            val item = client.trash(ROOT, "space", "Bearer synthetic").single()
            assertEquals("日本語 & café 😀.txt", item.name)
            assertEquals("/Docs/A & B.txt", item.originalPath)
            assertEquals(12L, item.sizeBytes)
        }
    }

    @Test fun versionsKeepNamespaceAndEscapedHref() {
        val xml =
            """<?xml version="1.0"?><multistatus xmlns="DAV:"><response><href>/remote.php/dav/meta/file/v/A&amp;B</href><propstat><prop><getcontentlength>12</getcontentlength><resourcetype/></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"""
        val client = FileVersionsClient(fixtureClient(xml.toByteArray(Charsets.UTF_8), "UTF-8"))
        val version = client.list(ROOT, "file", "Bearer synthetic").single()
        assertEquals("A&B", version.id)
        assertEquals(12L, version.sizeBytes)
    }

    private fun assertInvalid(
        fixture: String,
        block: () -> Unit,
    ) {
        val failure = assertThrows(fixture, OpenCloudException::class.java) { block() }
        assertEquals(fixture, OpenCloudError.InvalidResponse, failure.error)
        assertEquals(fixture, "The server returned incomplete or unexpected metadata.", failure.message)
        assertNull(fixture, failure.cause)
    }

    private fun fixtureClient(
        bytes: ByteArray,
        charset: String,
    ): OkHttpClient =
        OkHttpClient
            .Builder()
            .addInterceptor { chain ->
                Response
                    .Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(207)
                    .message("Synthetic DAV fixture")
                    .body(bytes.toResponseBody("application/xml; charset=$charset".toMediaType()))
                    .build()
            }.build()

    private companion object {
        const val ROOT = "https://cloud.example/remote.php/dav/spaces/space"
    }
}
