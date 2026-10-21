package eu.opencloud.android.next

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.network.DavOperationClient
import eu.opencloud.android.next.core.network.FavoriteSnapshotClient
import eu.opencloud.android.next.core.network.OpenCloudException
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Runs the production parser on Android's JAXP implementation, without a live server. */
@RunWith(AndroidJUnit4::class)
class AndroidDavParserTest {
    @Test fun parsesOperationPropertiesAndFavoritesOnAndroid() {
        val xml =
            """
            <d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
              <d:response><d:href>/dav/spaces/p/file.txt</d:href><d:propstat><d:prop>
                <d:resourcetype/><d:getcontentlength>3</d:getcontentlength>
                <d:getetag>"v1"</d:getetag><oc:fileid>file</oc:fileid>
              </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
            </d:multistatus>
            """.trimIndent()
        val client = responding(xml)
        assertEquals(
            3L,
            DavOperationClient(client).stat("https://cloud.example/dav/spaces/p/file.txt", "Bearer test")?.size,
        )
        assertEquals(
            setOf("file"),
            FavoriteSnapshotClient(client).snapshot(
                "https://cloud.example/dav/spaces",
                "Bearer test",
                mapOf(
                    "p" to "https://cloud.example/dav/spaces/p",
                ),
            )["p"],
        )
    }

    @Test fun rejectsEntityDeclarationsOnAndroid() {
        val client = responding("<!DOCTYPE x SYSTEM 'file:///private'><x/>")
        assertThrows(OpenCloudException::class.java) {
            DavOperationClient(client).stat("https://cloud.example/file", "Bearer test")
        }
    }

    private fun responding(xml: String) =
        OkHttpClient
            .Builder()
            .addInterceptor { chain ->
                Response
                    .Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(207)
                    .message("Multi-Status")
                    .header("Content-Range", "0-0/1")
                    .body(xml.toResponseBody())
                    .build()
            }.build()
}
