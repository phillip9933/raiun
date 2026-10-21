package eu.opencloud.android.next

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.network.VaultDavClient
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** OpenCloud Graph omits the root opaque ID; DAV retains it. No live credentials or network are used. */
@RunWith(AndroidJUnit4::class)
class AndroidVaultDavParserTest {
    @Test
    fun spaceRootKeepsFullDavIdentityWithMixedPropertyStatuses() {
        val http =
            OkHttpClient
                .Builder()
                .addInterceptor { chain ->
                    assertEquals("PROPFIND", chain.request().method)
                    Response
                        .Builder()
                        .request(chain.request())
                        .protocol(Protocol.HTTP_1_1)
                        .code(207)
                        .message("Multi-Status")
                        .body(SPACE_ROOT.toResponseBody("application/xml".toMediaType()))
                        .build()
                }.build()
        val listing =
            VaultDavClient(http).list(
                "https://vault.invalid/dav/spaces/storage\$space",
                authorization = "Bearer synthetic-test-only",
                recognizedVaultRoot = true,
            )
        assertEquals("storage\$space!space", listing.root.id)
        assertTrue(listing.root.isFolder)
        assertTrue(listing.children.isEmpty())
    }

    private companion object {
        val SPACE_ROOT =
            """
            <d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:crypt="ocrclone">
              <d:response>
                <d:href>/dav/spaces/storage${'$'}space/</d:href>
                <d:propstat><d:prop>
                  <oc:fileid>storage${'$'}space!space</oc:fileid>
                  <oc:id>storage${'$'}space!space</oc:id>
                  <oc:name>Encrypted Space</oc:name>
                  <oc:size>0</oc:size>
                  <d:resourcetype><d:collection/></d:resourcetype>
                  <d:getetag>"synthetic-root"</d:getetag>
                </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
                <d:propstat><d:prop>
                  <d:getcontentlength/><d:getcontenttype/><crypt:integrity-id/>
                </d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
              </d:response>
            </d:multistatus>
            """.trimIndent()
    }
}
