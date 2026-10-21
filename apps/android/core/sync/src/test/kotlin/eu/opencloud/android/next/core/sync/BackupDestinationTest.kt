package eu.opencloud.android.next.core.sync

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupDestinationTest {
    @Test fun `missing camera destination is created and confirmed before uploads`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(folderResponse())
            assertTrue(
                ensureBackupCollections(
                    server.url("/dav").toString(),
                    "/Camera Uploads",
                    OkHttpClient(),
                    "Bearer test",
                ),
            )
            assertEquals("PROPFIND", server.takeRequest().method)
            val create = server.takeRequest()
            assertEquals("MKCOL", create.method)
            assertEquals("/dav/Camera%20Uploads", create.path)
            assertEquals("PROPFIND", server.takeRequest().method)
            server.enqueue(folderResponse())
            assertFalse(
                ensureBackupCollections(
                    server.url("/dav").toString(),
                    "/Camera Uploads",
                    OkHttpClient(),
                    "Bearer test",
                ),
            )
            assertEquals("PROPFIND", server.takeRequest().method)
        }
    }

    @Test fun `backup directory path cannot escape the discovered root`() {
        MockWebServer().use { server ->
            assertThrows(IllegalArgumentException::class.java) {
                ensureBackupCollections(server.url("/dav").toString(), "/../outside", OkHttpClient(), "Bearer test")
            }
            assertEquals(0, server.requestCount)
        }
    }

    @Test fun `cancelled collection preparation does not send a subsequent create`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(404))
            var checks = 0
            assertThrows(kotlinx.coroutines.CancellationException::class.java) {
                ensureBackupCollections(
                    server.url("/dav").toString(),
                    "/Camera Uploads",
                    OkHttpClient(),
                    "Bearer test",
                ) {
                    if (++checks == 2) throw kotlinx.coroutines.CancellationException()
                }
            }
            assertEquals(1, server.requestCount)
            assertEquals("PROPFIND", server.takeRequest().method)
        }
    }

    private fun folderResponse() =
        MockResponse().setResponseCode(207).setBody(
            """<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/Camera%20Uploads</d:href>
        <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"v1"</d:getetag>
        </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
        )
}
