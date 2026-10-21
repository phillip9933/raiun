package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.CancellationException

class DownloadChecksumTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun resumedPartHashesItsEntireContents() {
        MockWebServer().use { server ->
            server.start()
            val part = temporary.newFile("download.part")
            part.writeText("he") // Previously verified range retained for resume.
            part.appendText("llo")
            server.enqueue(properties("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"))
            verifyDownloadChecksum(
                TransferClient(OkHttpClient()),
                DownloadChecksumSource(server.url("/file").toString(), "Bearer test", DownloadExpectation(5, "\"v1\"")),
                part,
            ) {
            }
            assertEquals("PROPFIND", server.takeRequest().method)

            part.writeText("jello")
            server.enqueue(properties("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"))
            val mismatch =
                assertThrows(OpenCloudException::class.java) {
                    verifyDownloadChecksum(
                        TransferClient(OkHttpClient()),
                        DownloadChecksumSource(
                            server.url("/file").toString(),
                            "Bearer test",
                            DownloadExpectation(5, "\"v1\""),
                        ),
                        part,
                    ) {
                    }
                }
            assertEquals(OpenCloudError.DownloadIntegrity, mismatch.error)
        }
    }

    @Test fun cancellationDuringHashStopsWithoutPublishing() {
        MockWebServer().use { server ->
            server.start()
            val part = temporary.newFile("large.part")
            part.writeBytes(ByteArray(256 * 1024) { 'a'.code.toByte() })
            server.enqueue(properties("0".repeat(64), 256 * 1024))
            var checks = 0
            assertThrows(CancellationException::class.java) {
                verifyDownloadChecksum(
                    TransferClient(OkHttpClient()),
                    DownloadChecksumSource(
                        server.url("/file").toString(),
                        "Bearer test",
                        DownloadExpectation(256L * 1024, "\"v1\""),
                    ),
                    part,
                ) {
                    if (++checks > 2) throw CancellationException()
                }
            }
            assertTrue(checks > 2)
        }
    }

    @Test fun cancellationAfterUnsupportedProbeStopsPublication() {
        MockWebServer().use { server ->
            server.start()
            val part = temporary.newFile("optional.part").apply { writeText("hello") }
            server.enqueue(MockResponse().setResponseCode(405))
            var checks = 0
            assertThrows(CancellationException::class.java) {
                verifyDownloadChecksum(
                    TransferClient(OkHttpClient()),
                    DownloadChecksumSource(
                        server.url("/file").toString(),
                        "Bearer test",
                        DownloadExpectation(5, "\"v1\""),
                    ),
                    part,
                ) {
                    if (++checks == 2) throw CancellationException()
                }
            }
            assertEquals(2, checks)
        }
    }

    @Test fun badDigestDropsResumeCheckpointButProbeFailureRetainsIt() {
        MockWebServer().use { server ->
            server.start()
            val part = temporary.newFile("checkpoint.part").apply { writeText("jello") }
            val validator = temporary.newFile("checkpoint.validator").apply { writeText("version") }
            val client = TransferClient(OkHttpClient())
            val url = server.url("/file").toString()
            server.enqueue(MockResponse().setResponseCode(401))
            assertThrows(OpenCloudException::class.java) {
                verifyCheckpointedDownloadChecksum(
                    client,
                    DownloadChecksumSource(url, "Bearer test", DownloadExpectation(5, "\"v1\"")),
                    part,
                    validator,
                ) {}
            }
            assertTrue(part.exists() && validator.exists())
            server.enqueue(properties("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"))
            val mismatch =
                assertThrows(OpenCloudException::class.java) {
                    verifyCheckpointedDownloadChecksum(
                        client,
                        DownloadChecksumSource(url, "Bearer test", DownloadExpectation(5, "\"v1\"")),
                        part,
                        validator,
                    ) {}
                }
            assertEquals(OpenCloudError.DownloadIntegrity, mismatch.error)
            assertTrue(!part.exists() && !validator.exists())
        }
    }

    private fun properties(
        sha256: String,
        size: Int = 5,
    ) = MockResponse().setResponseCode(207).setBody(
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/file</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>$size</d:getcontentlength><d:getetag>"v1"</d:getetag><oc:checksums><oc:checksum>SHA256:$sha256</oc:checksum></oc:checksums></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
    )
}
