package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.ContentFingerprint
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.network.TransferConflictException
import eu.opencloud.android.next.core.network.TransferHttpException
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class UploadRecoveryTest {
    @Test fun `manual retry retains verification intent even with a reset attempt counter`() =
        runTest {
            var writes = 0
            var checks = 0
            uploadAndVerify(
                intent.copy(attemptCount = 1, verificationPending = true),
                upload = { writes++ },
                verify = { checks++ },
            )
            assertEquals(0, writes)
            assertEquals(1, checks)
        }

    private val intent =
        TransferEntity(
            "upload",
            "a",
            "s",
            null,
            "UPLOAD",
            "content://source",
            "/file",
            "file",
            null,
            5,
            bytesTransferred = 5,
            attemptCount = 2,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    @Test fun `complete checkpoint verifies remote bytes without replaying PUT`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setBody("hello"))
                execute(server, intent)
                assertEquals("GET", server.takeRequest().method)
                assertEquals(1, server.requestCount)
            }
        }

    @Test fun `changed remote bytes after complete checkpoint fail without an overwrite`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setBody("other"))
                try {
                    execute(server, intent)
                    org.junit.Assert.fail("Changed remote bytes must not complete recovery")
                } catch (failure: OpenCloudException) {
                    assertEquals(OpenCloudError.PreconditionFailed, failure.error)
                }
                assertEquals("GET", server.takeRequest().method)
                assertEquals(1, server.requestCount)
            }
        }

    @Test fun `missing destination after full progress uses conditional recovery and verifies bytes`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(201))
                server.enqueue(MockResponse().setBody("hello"))
                execute(server, intent)
                assertEquals("GET", server.takeRequest().method)
                assertEquals("HEAD", server.takeRequest().method)
                assertEquals("*", server.takeRequest().getHeader("If-None-Match"))
                assertEquals("GET", server.takeRequest().method)
            }
        }

    @Test fun `checksum verification of missing target safely recreates it once`() =
        runTest {
            MockWebServer().use { server ->
                val present = AtomicBoolean(false)
                val writes = AtomicInteger()
                val condition = AtomicReference<String?>()
                server.dispatcher =
                    object : Dispatcher() {
                        override fun dispatch(request: RecordedRequest): MockResponse =
                            when (request.method) {
                                "PROPFIND", "GET", "HEAD" ->
                                    if (!present.get()) {
                                        MockResponse().setResponseCode(404)
                                    } else if (request.method == "GET") {
                                        MockResponse().setBody("hello")
                                    } else {
                                        MockResponse().setResponseCode(405)
                                    }
                                "PUT" -> {
                                    writes.incrementAndGet()
                                    condition.set(request.getHeader("If-None-Match"))
                                    present.set(true)
                                    MockResponse().setResponseCode(201)
                                }
                                else -> MockResponse().setResponseCode(500)
                            }
                    }

                execute(server, intent, useServerChecksum = true)

                assertEquals(1, writes.get())
                assertEquals("*", condition.get())
            }
        }

    @Test fun `checksum verification of a pending target never replays a completed upload`() =
        runTest {
            MockWebServer().use { server ->
                val writes = AtomicInteger()
                server.dispatcher =
                    object : Dispatcher() {
                        override fun dispatch(request: RecordedRequest): MockResponse =
                            if (request.method == "PUT") {
                                writes.incrementAndGet()
                                MockResponse().setResponseCode(201)
                            } else {
                                MockResponse().setResponseCode(425)
                            }
                    }

                try {
                    execute(server, intent, useServerChecksum = true)
                    org.junit.Assert.fail("A pending target must still require verification")
                } catch (failure: TransferHttpException) {
                    assertEquals(425, failure.statusCode)
                }
                assertEquals(0, writes.get())
            }
        }

    @Test fun `checksum verification of changed remote bytes never overwrites`() =
        runTest {
            MockWebServer().use { server ->
                val writes = AtomicInteger()
                server.dispatcher =
                    object : Dispatcher() {
                        override fun dispatch(request: RecordedRequest): MockResponse =
                            when (request.method) {
                                "PROPFIND" -> MockResponse().setResponseCode(405)
                                "GET" -> MockResponse().setBody("other")
                                "PUT" -> {
                                    writes.incrementAndGet()
                                    MockResponse().setResponseCode(201)
                                }
                                else -> MockResponse().setResponseCode(500)
                            }
                    }

                try {
                    execute(server, intent, useServerChecksum = true)
                    org.junit.Assert.fail("Changed remote bytes must require attention")
                } catch (failure: OpenCloudException) {
                    assertEquals(OpenCloudError.PreconditionFailed, failure.error)
                }
                assertEquals(0, writes.get())
            }
        }

    @Test fun `a racing different file during missing recovery remains a conflict`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(412))
                server.enqueue(MockResponse().setBody("other"))
                try {
                    execute(server, intent)
                    org.junit.Assert.fail("The competing file must survive")
                } catch (_: TransferConflictException) {
                    assertEquals(4, server.requestCount)
                }
                server.takeRequest()
                assertEquals("HEAD", server.takeRequest().method)
                assertEquals("*", server.takeRequest().getHeader("If-None-Match"))
            }
        }

    @Test fun `missing edited files and explicit overwrites are never recreated automatically`() =
        runTest {
            for (transfer in listOf(intent.copy(expectedETag = "\"original\""), intent.copy(overwrite = true))) {
                try {
                    uploadAndVerify(transfer, upload = { error("must not write") }, verify = {
                        throw TransferHttpException(404)
                    })
                    org.junit.Assert.fail("Missing target must require attention")
                } catch (failure: TransferHttpException) {
                    assertEquals(404, failure.statusCode)
                }
            }
        }

    @Test fun `a competing target during a new upload is never retried unconditionally`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(412))
                try {
                    execute(server, intent.copy(bytesTransferred = 0, attemptCount = 1))
                    org.junit.Assert.fail("Competing content must require an explicit conflict decision")
                } catch (_: TransferConflictException) {
                    assertEquals(2, server.requestCount)
                }
                assertEquals("HEAD", server.takeRequest().method)
                val request = server.takeRequest()
                assertEquals("PUT", request.method)
                assertEquals("*", request.getHeader("If-None-Match"))
            }
        }

    @Test fun `partial checkpoint uploads then verifies the full content`() =
        runTest {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(201))
                server.enqueue(MockResponse().setBody("hello"))
                execute(server, intent.copy(bytesTransferred = 3))
                assertEquals("HEAD", server.takeRequest().method)
                val put = server.takeRequest()
                assertEquals("PUT", put.method)
                assertEquals("*", put.getHeader("If-None-Match"))
                assertEquals("hello", put.body.readUtf8())
                assertEquals("GET", server.takeRequest().method)
                assertEquals(3, server.requestCount)
            }
        }

    @Test fun `verification 425 never repeats a completed write`() =
        runTest {
            var current = intent.copy(bytesTransferred = 0, attemptCount = 1)
            var writes = 0
            var checks = 0
            repeat(3) {
                try {
                    uploadAndVerify(current, upload = { writes++ }, uploaded = {
                        current = current.copy(bytesTransferred = current.bytesTotal)
                    }, verify = {
                        if (++checks < 3) throw TransferHttpException(425, 30)
                    })
                } catch (failure: TransferHttpException) {
                    assertEquals(425, failure.statusCode)
                }
                current = current.copy(attemptCount = current.attemptCount + 1)
            }
            assertEquals(1, writes)
            assertEquals(3, checks)
        }

    @Test fun `empty recovery probes first and only missing remote bytes allow a write`() =
        runTest {
            var writes = 0
            var checks = 0
            val empty = intent.copy(bytesTotal = 0, bytesTransferred = 0)
            uploadAndVerify(empty, upload = { writes++ }, verify = { checks++ })
            assertEquals(0, writes)
            uploadAndVerify(empty, upload = { writes++ }, verify = {
                if (++checks == 2) throw TransferHttpException(404)
            })
            assertEquals(1, writes)
            assertEquals(3, checks)
        }

    @Test fun `first attempt reports conflict even when existing target has identical bytes`() =
        runTest {
            var checks = 0
            try {
                uploadAndVerify(intent.copy(bytesTransferred = 0, attemptCount = 1), upload = {
                    throw TransferConflictException()
                }, verify = { checks++ })
                org.junit.Assert.fail("A pre-existing target must require an explicit conflict decision")
            } catch (_: TransferConflictException) {
                assertEquals(0, checks)
            }
        }

    @Test fun `later attempt may reconcile an identical target after an ambiguous write`() =
        runTest {
            var checks = 0
            uploadAndVerify(intent.copy(bytesTransferred = 0, attemptCount = 2), upload = {
                throw TransferConflictException()
            }, verify = { checks++ })
            assertEquals(1, checks)
        }

    private suspend fun execute(
        server: MockWebServer,
        transfer: TransferEntity,
        useServerChecksum: Boolean = false,
    ) {
        val client = TransferClient(OkHttpClient())
        val url = server.url("file").toString()
        val bytes = "hello".toByteArray()
        val fingerprint = ContentFingerprint.read(bytes.inputStream(), 5) {}
        uploadAndVerify(
            transfer,
            upload = { client.upload(url, "Bearer test", null, 5, false, { bytes.inputStream() }) {} },
            verify = { client.verifyUpload(url, "Bearer test", fingerprint, useServerChecksum) {} },
        )
    }
}
