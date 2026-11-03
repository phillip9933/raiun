package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileOperationEntity
import eu.opencloud.android.next.core.network.DavOperationClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class FileOperationTest {
    @Test fun `numbered copies preserve file extensions and complete folder names`() {
        assertEquals("photo (1).jpg", numberedCopyName("photo.jpg", false, 1))
        assertEquals("photo (2).jpg", numberedCopyName("photo.jpg", false, 2))
        assertEquals("Project.v2 (1)", numberedCopyName("Project.v2", true, 1))
        assertEquals(".hidden (1)", numberedCopyName(".hidden", false, 1))
    }

    @Test fun `numbered destination skips reserved siblings in the target folder`() =
        runTest {
            val probes = mutableListOf<String>()
            val chosen =
                availableOperationName("photo.jpg", false, "/target") {
                    probes += it
                    it in setOf("/target/photo (1).jpg", "/target/photo (2).jpg")
                }
            assertEquals("photo (3).jpg", chosen)
            assertEquals(listOf("/target/photo (1).jpg", "/target/photo (2).jpg", "/target/photo (3).jpg"), probes)
        }

    @Test fun `destination collision in copy or move never journals sends or deletes`() =
        runTest {
            for (move in listOf(false, true)) {
                MockWebServer().use { server ->
                    val backend = Backend()
                    backend.files["/target"] = "existing"
                    server.dispatcher = backend
                    var sent = false
                    try {
                        executeFileOperation(
                            operation(server).copy(move = move),
                            DavOperationClient(OkHttpClient()),
                            "Bearer test",
                            {},
                        ) { sent = true }
                        org.junit.Assert.fail("Collision must be surfaced")
                    } catch (failure: OpenCloudException) {
                        assertEquals(OpenCloudError.Conflict, failure.error)
                        assertFalse(sent)
                        assertEquals(emptyList<String>(), backend.mutations)
                        assertEquals("hello", backend.files["/source"])
                        assertEquals("existing", backend.files["/target"])
                    }
                }
            }
        }

    @Test fun `server checksum verifies copy without downloading file bytes`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend(checksums = true)
                server.dispatcher = backend
                var fingerprint = ""
                executeFileOperation(operation(server), DavOperationClient(OkHttpClient()), "Bearer test", {}) {
                    fingerprint = it
                }
                assertTrue(fingerprint.startsWith("checksum-v1:SHA-256:5:"))
                assertEquals(0, backend.downloads)
                assertEquals(listOf("COPY"), backend.mutations)
            }
        }

    @Test fun `checksum mismatch cannot delete cross space move source`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend(checksums = true, corruptTarget = true)
                server.dispatcher = backend
                try {
                    executeFileOperation(
                        operation(server).copy(move = true),
                        DavOperationClient(OkHttpClient()),
                        "Bearer test",
                        {},
                    ) {}
                    org.junit.Assert.fail("Mismatching content must fail verification")
                } catch (_: OpenCloudException) {
                    assertEquals("hello", backend.files["/source"])
                    assertEquals(listOf("COPY"), backend.mutations)
                    assertEquals(0, backend.downloads)
                }
            }
        }

    @Test fun `cross space file move verifies copy before conditional source deletion`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend()
                server.dispatcher = backend
                var deleting = false
                executeFileOperation(
                    operation(server).copy(move = true),
                    DavOperationClient(OkHttpClient()),
                    "Bearer test",
                    {},
                    markDeleting = {
                        assertEquals("hello", backend.files["/target"])
                        assertEquals("hello", backend.files["/source"])
                        deleting = true
                    },
                ) {}
                assertTrue(deleting)
                assertEquals(listOf("COPY", "DELETE"), backend.mutations)
                assertFalse(backend.files.containsKey("/source"))
            }
        }

    @Test fun `copy verifies content and never deletes source`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend()
                server.dispatcher = backend
                val operation = operation(server)
                var sent = false
                executeFileOperation(operation, DavOperationClient(OkHttpClient()), "Bearer test", {}) { sent = true }
                assertTrue(sent)
                assertEquals("hello", backend.files["/target"])
                assertEquals("hello", backend.files["/source"])
                assertEquals(listOf("COPY"), backend.mutations)
            }
        }

    @Test fun `copy waits for destination metadata to become visible after server acknowledgement`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend(staleTargetPropfinds = 2)
                server.dispatcher = backend

                executeFileOperation(operation(server), DavOperationClient(OkHttpClient()), "Bearer test", {}) {}

                assertEquals("hello", backend.files["/target"])
                assertEquals(listOf("COPY"), backend.mutations)
                assertEquals(2, backend.staleTargetResponses)
            }
        }

    @Test fun `lost MOVE response reconciles without repeating mutation`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend(disconnect = true)
                server.dispatcher = backend
                val client = DavOperationClient(OkHttpClient())
                val operation = operation(server).copy(move = true, destinationSpaceId = "s")
                var fingerprint: String? = null
                try {
                    executeFileOperation(operation, client, "Bearer test", {}) { fingerprint = it }
                    org.junit.Assert.fail("Response should be lost")
                } catch (_: IOException) {
                    assertTrue(fingerprint != null)
                }
                executeFileOperation(
                    operation.copy(state = "SENT", fingerprint = fingerprint),
                    client,
                    "Bearer test",
                    {},
                ) {
                    org.junit.Assert.fail("Recovery must not send another mutation")
                }
                assertFalse(backend.files.containsKey("/source"))
                assertEquals("hello", backend.files["/target"])
                assertEquals(listOf("MOVE"), backend.mutations)
            }
        }

    @Test fun `occupied destination is preserved and cancellation before send performs no mutation`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend()
                backend.files["/target"] = "other"
                server.dispatcher = backend
                val operation = operation(server)
                try {
                    executeFileOperation(operation, DavOperationClient(OkHttpClient()), "Bearer test", {}) {}
                    org.junit.Assert.fail("Conflict must fail")
                } catch (_: OpenCloudException) {
                    assertEquals("other", backend.files["/target"])
                }
                backend.files.remove("/target")
                try {
                    executeFileOperation(operation, DavOperationClient(OkHttpClient()), "Bearer test", {}) {
                        throw CancellationException()
                    }
                    org.junit.Assert.fail("Cancellation must escape")
                } catch (_: CancellationException) {
                    assertTrue(backend.mutations.isEmpty())
                }
            }
        }

    @Test fun `journal before dispatch recovers missing destination with guarded copy and move`() =
        runTest {
            for (move in listOf(false, true)) {
                MockWebServer().use { server ->
                    val backend = Backend()
                    server.dispatcher = backend
                    val client = DavOperationClient(OkHttpClient())
                    val operation = operation(server).copy(move = move, destinationSpaceId = "s")
                    var fingerprint: String? = null
                    try {
                        executeFileOperation(operation, client, "Bearer test", {}) {
                            fingerprint = it
                            throw CancellationException()
                        }
                    } catch (_: CancellationException) {
                        assertTrue(backend.mutations.isEmpty())
                    }
                    executeFileOperation(
                        operation.copy(state = "SENT", fingerprint = fingerprint),
                        client,
                        "Bearer test",
                        {},
                    ) {
                        org.junit.Assert.fail("An existing journal must remain intact")
                    }
                    assertEquals("hello", backend.files["/target"])
                    assertEquals(listOf(if (move) "MOVE" else "COPY"), backend.mutations)
                    assertEquals(!move, backend.files.containsKey("/source"))
                }
            }
        }

    @Test fun `missing destination recovery rejects changed source even with reused etag`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend()
                server.dispatcher = backend
                val client = DavOperationClient(OkHttpClient())
                val fingerprint = client.verificationFingerprint(server.url("/source").toString(), "Bearer test") {}
                backend.files["/source"] = "other"
                try {
                    executeFileOperation(
                        operation(server).copy(state = "SENT", fingerprint = fingerprint),
                        client,
                        "Bearer test",
                        {},
                    ) {}
                    org.junit.Assert.fail("Changed source must not be replayed")
                } catch (failure: OpenCloudException) {
                    assertEquals(OpenCloudError.PreconditionFailed, failure.error)
                    assertTrue(backend.mutations.isEmpty())
                    assertFalse(backend.files.containsKey("/target"))
                }
            }
        }

    @Test fun `late original wins guarded replay without overwrite or duplicate mutation`() =
        runTest {
            MockWebServer().use { server ->
                val backend = Backend(lateOriginal = true)
                server.dispatcher = backend
                val client = DavOperationClient(OkHttpClient())
                val fingerprint = client.verificationFingerprint(server.url("/source").toString(), "Bearer test") {}
                executeFileOperation(
                    operation(server).copy(state = "SENT", fingerprint = fingerprint),
                    client,
                    "Bearer test",
                    {},
                ) {}
                assertEquals("hello", backend.files["/target"])
                assertEquals(emptyList<String>(), backend.mutations)
            }
        }

    @Test fun `late original before replay source validation verifies destination without resending`() =
        runTest {
            for (move in listOf(false, true)) {
                MockWebServer().use { server ->
                    val backend = Backend(lateOriginalOnMissingProbe = move)
                    server.dispatcher = backend
                    val client = DavOperationClient(OkHttpClient())
                    val fingerprint = client.verificationFingerprint(server.url("/source").toString(), "Bearer test") {}
                    executeFileOperation(
                        operation(
                            server,
                        ).copy(move = move, destinationSpaceId = "s", state = "SENT", fingerprint = fingerprint),
                        client,
                        "Bearer test",
                        {},
                    ) {}
                    assertEquals("hello", backend.files["/target"])
                    assertTrue(backend.mutations.isEmpty())
                    assertEquals(if (move) null else "other", backend.files["/source"])
                }
            }
        }

    private fun operation(server: MockWebServer) =
        FileOperationEntity(
            "op",
            "a",
            "s",
            "t",
            "source-id",
            null,
            null,
            server.url("/").toString(),
            server.url("/").toString(),
            "/source",
            "/target",
            "\"v1\"",
            false,
        )

    private class Backend(
        private val disconnect: Boolean = false,
        private val lateOriginal: Boolean = false,
        private val lateOriginalOnMissingProbe: Boolean? = null,
        private val checksums: Boolean = false,
        private val corruptTarget: Boolean = false,
        private var staleTargetPropfinds: Int = 0,
    ) : Dispatcher() {
        val files =
            java.util.concurrent
                .ConcurrentHashMap<String, String>()
                .apply { put("/source", "hello") }
        val mutations = mutableListOf<String>()
        var downloads = 0
        var staleTargetResponses = 0

        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = requireNotNull(request.path)
            val content = files[path]
            return when (request.method) {
                "PROPFIND" -> properties(path, content)
                "GET" -> {
                    downloads++
                    MockResponse().setHeader("ETag", "\"v1\"").setBody(requireNotNull(content))
                }
                "MOVE", "COPY" -> mutate(request, path, content)
                "DELETE" -> {
                    assertEquals("\"v1\"", request.getHeader("If-Match"))
                    mutations.add("DELETE")
                    files.remove(path)
                    MockResponse().setResponseCode(204)
                }
                else -> MockResponse().setResponseCode(405)
            }
        }

        private fun properties(
            path: String,
            content: String?,
        ): MockResponse =
            if (content == null) {
                if (path == "/target" && lateOriginalOnMissingProbe != null) {
                    files["/target"] = requireNotNull(files["/source"])
                    if (lateOriginalOnMissingProbe) files.remove("/source") else files["/source"] = "other"
                }
                MockResponse().setResponseCode(404)
            } else if (path == "/target" && staleTargetPropfinds > 0) {
                staleTargetPropfinds--
                staleTargetResponses++
                MockResponse().setResponseCode(404)
            } else {
                MockResponse().setResponseCode(207).setBody(
                    "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">" +
                        "<d:response><d:href>$path</d:href><d:propstat><d:prop>" +
                        "<d:resourcetype/><d:getcontentlength>${content.length}</d:getcontentlength>" +
                        "<d:getetag>\"v1\"</d:getetag>" +
                        (
                            if (checksums) {
                                "<oc:checksums><oc:checksum>SHA256:${sha256(
                                    content,
                                )}</oc:checksum></oc:checksums>"
                            } else {
                                ""
                            }
                        ) +
                        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
                )
            }

        private fun mutate(
            request: RecordedRequest,
            path: String,
            content: String?,
        ): MockResponse {
            assertEquals("F", request.getHeader("Overwrite"))
            assertEquals("\"v1\"", request.getHeader("If-Match"))
            if (lateOriginal) files["/target"] = requireNotNull(content)
            if (files.containsKey("/target")) return MockResponse().setResponseCode(412)
            mutations.add(requireNotNull(request.method))
            files["/target"] = if (corruptTarget) "other" else requireNotNull(content)
            if (request.method == "MOVE") files.remove(path)
            return if (disconnect) {
                MockResponse().setSocketPolicy(
                    SocketPolicy.DISCONNECT_AFTER_REQUEST,
                )
            } else {
                MockResponse().setResponseCode(201)
            }
        }

        private fun sha256(value: String) =
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(value.toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
