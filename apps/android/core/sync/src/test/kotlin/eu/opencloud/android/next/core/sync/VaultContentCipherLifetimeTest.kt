package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class VaultContentCipherLifetimeTest {
    private val cipher = VaultBoundaryTestCipher()
    private val server = MockWebServer()
    private val staging = Files.createTempDirectory("content-cipher-lifetime").toFile()
    private val mutations = AtomicInteger()
    private lateinit var session: VaultSession

    @Before fun prepare() {
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    if (request.method == "PROPFIND") {
                        MockResponse().setResponseCode(207).setBody(ROOT_XML)
                    } else if (request.method == "GET") {
                        MockResponse()
                            .setHeader(
                                "ETag",
                                "\"v1\"",
                            ).setBody(Buffer().write(cipher.encryptBytes(ByteArray(65537) { 7 })))
                    } else {
                        mutations.incrementAndGet()
                        MockResponse().setResponseCode(500)
                    }
            }
        server.start()
        val account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", false)
        val location =
            VaultLocation(
                account.id,
                "Secret.vault",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault",
                "root",
                account.serverUrl,
                server.url("dav/").toString(),
                "Secret.vault",
                true,
            )
        session =
            VaultSession(
                VaultIdentity(account.id, account.serverUrl, "drive", "vault"),
                location,
                cipher,
                VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                VaultAccess(account, account.serverUrl, "Bearer synthetic", OkHttpClient(), { true }, { account }),
                { true },
                staging,
            )
    }

    @After fun close() {
        session.close()
        server.shutdown()
        staging.deleteRecursively()
    }

    @Test fun `session close disposes stalled fork once before provider returns and prevents publication`() {
        val input = StalledInput()
        runStalled(input.gate, { upload(input) }) { _ ->
            session.close()
            session.close()
            assertTrue(cipher.closed.get())
            assertClosedOnce()
        }
        assertClosedOnce()
        assertNoPublication()
    }

    @Test fun `cancellation alone disposes stalled fork once without closing the live session`() {
        val input = StalledInput()
        runStalled(input.gate, { upload(input) }) { job ->
            job.cancel()
            assertFalse(cipher.closed.get())
            assertClosedOnce()
        }
        assertClosedOnce()
        assertNoPublication()
    }

    @Test fun `session close revokes a stalled plaintext consumer before it returns`() {
        val output = StalledOutput()
        runStalled(output.gate, { session.readBoundary(sourceEntry(), output) }) { _ ->
            session.close()
            assertClosedOnce()
        }
        assertClosedOnce()
        assertTrue(requireNotNull(output.borrowed).all { it == 0.toByte() })
        assertNoPublication()
    }

    @Test fun `cancellation revokes a stalled plaintext consumer without closing the session`() {
        val output = StalledOutput()
        runStalled(output.gate, { session.readBoundary(sourceEntry(), output) }) { job ->
            job.cancel()
            assertClosedOnce()
            assertFalse(cipher.closed.get())
        }
        assertClosedOnce()
        assertTrue(requireNotNull(output.borrowed).all { it == 0.toByte() })
        assertNoPublication()
    }

    private fun sourceEntry() = BoundaryEntry("file", "note.bin", "note.bin", false, 65537, "\"v1\"")

    @Test fun `session close during final flush prevents late download success`() {
        val output = StalledOutput(stallOnFlush = true)
        runStalled(output.gate, { session.readBoundary(sourceEntry(), output) }) { _ -> session.close() }
        assertClosedOnce()
        assertNoPublication()
    }

    @Test fun `cancellation during final flush prevents late download success`() {
        val output = StalledOutput(stallOnFlush = true)
        runStalled(output.gate, { session.readBoundary(sourceEntry(), output) }) { job -> job.cancel() }
        assertClosedOnce()
        assertFalse(cipher.closed.get())
        assertNoPublication()
    }

    @Test fun `already cancelled content operation never allocates a fork`() {
        val cancelled = Job().apply { cancel() }
        assertThrows(CancellationException::class.java) {
            runBlocking { withContext(cancelled) { upload(untouchedInput()) } }
        }
        assertTrue(cipher.forks.isEmpty())
        assertNoPublication()
    }

    @Test fun `session close during fork creation rejects late admission and disposes returned fork`() {
        val gate = Gate()
        cipher.onFork = { gate.await() }
        runStalled(gate, { upload(untouchedInput()) }, creationInProgress = true) { _ -> session.close() }
        assertClosedOnce()
        assertNoPublication()
    }

    @Test fun `cancellation before fork registration cannot start content and disposes returned fork`() {
        val gate = Gate()
        cipher.onFork = { gate.await() }
        runStalled(gate, { upload(untouchedInput()) }, creationInProgress = true) { job -> job.cancel() }
        assertFalse(cipher.closed.get())
        assertClosedOnce()
        assertNoPublication()
    }

    @Test fun `synchronous factory cancellation cannot orphan its returned fork`() {
        assertThrows(CancellationException::class.java) {
            runBlocking {
                val job = requireNotNull(currentCoroutineContext()[Job])
                cipher.onFork = { job.cancel() }
                upload(untouchedInput())
            }
        }
        assertClosedOnce()
        assertFalse(cipher.closed.get())
        assertNoPublication()
    }

    @Test fun `synchronous factory session close cannot admit or orphan its returned fork`() {
        cipher.onFork = { session.close() }
        assertThrows(OpenCloudException::class.java) { runBlocking { upload(untouchedInput()) } }
        assertClosedOnce()
        assertTrue(cipher.closed.get())
        assertNoPublication()
    }

    @Test fun `late background preparation after session close cannot publish ciphertext payload`() {
        val input = StalledInput()
        val payloads = VaultUploadStore(staging.resolve("payloads"))
        runStalled(input.gate, {
            session.prepareBackgroundUpload(payloads, "", "copy.bin", input, -1, { true })
        }) { _ -> session.close() }
        assertTrue(cipher.closed.get())
        assertTrue(payloads.ids().isEmpty())
        assertNoPublication()
    }

    @Test fun `cancelled background preparation cannot publish ciphertext payload`() {
        val input = StalledInput()
        val payloads = VaultUploadStore(staging.resolve("payloads"))
        runStalled(input.gate, {
            session.prepareBackgroundUpload(payloads, "", "copy.bin", input, -1, { true })
        }) { job -> job.cancel() }
        assertFalse(cipher.closed.get())
        assertTrue(payloads.ids().isEmpty())
        assertNoPublication()
    }

    private suspend fun upload(input: InputStream) = session.uploadBoundary("", "copy.bin", input, -1, null)

    private fun untouchedInput() =
        object : InputStream() {
            override fun read(): Int = error("Content started after its admission was revoked")
        }

    private fun assertClosedOnce() {
        assertEquals(1, cipher.forks.size)
        assertTrue(
            cipher.forks
                .single()
                .closed
                .get(),
        )
        assertEquals(
            1,
            cipher.forks
                .single()
                .closeCount
                .get(),
        )
    }

    private fun assertNoPublication() {
        assertEquals(0, mutations.get())
        assertEquals(0, session.issuedEntryCountForTesting())
        assertTrue(staging.walkTopDown().none { it.isFile })
    }

    private fun runStalled(
        gate: Gate,
        operation: suspend () -> Any,
        creationInProgress: Boolean = false,
        revoke: (Job) -> Unit,
    ) {
        val executor = Executors.newFixedThreadPool(2)
        val job = AtomicReference<Job>()
        val task =
            executor.submit<Throwable?> {
                runCatching {
                    runBlocking {
                        job.set(requireNotNull(currentCoroutineContext()[Job]))
                        operation()
                    }
                }.exceptionOrNull()
            }
        try {
            assertTrue("External operation did not start", gate.entered.await(10, TimeUnit.SECONDS))
            val revoking = CountDownLatch(1)
            val revocation =
                executor.submit {
                    revoking.countDown()
                    revoke(requireNotNull(job.get()))
                }
            assertTrue(revoking.await(5, TimeUnit.SECONDS))
            if (creationInProgress) {
                // No revoker may return while the fork is live but creation has not handed it off.
                assertThrows(TimeoutException::class.java) { revocation.get(100, TimeUnit.MILLISECONDS) }
                assertFalse(
                    cipher.forks
                        .single()
                        .closed
                        .get(),
                )
            } else {
                revocation.get(1, TimeUnit.SECONDS)
            }
            assertFalse("Provider should remain stalled until explicitly released", task.isDone)
            gate.release.countDown()
            revocation.get(5, TimeUnit.SECONDS)
            if (creationInProgress) assertClosedOnce()
            assertNotNull("Revoked content operation succeeded", task.get(10, TimeUnit.SECONDS))
        } finally {
            gate.release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        }
    }

    private class Gate {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun await() {
            entered.countDown()
            assertTrue("Fixture release timed out", release.await(15, TimeUnit.SECONDS))
        }
    }

    private class StalledInput : ByteArrayInputStream(byteArrayOf(1, 2, 3)) {
        val gate = Gate()

        override fun read(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            gate.await()
            return super.read(bytes, offset, length)
        }
    }

    private class StalledOutput(
        private val stallOnFlush: Boolean = false,
    ) : OutputStream() {
        val gate = Gate()
        var borrowed: ByteArray? = null

        override fun write(value: Int): Unit = error("Expected block writes")

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            borrowed = bytes
            if (!stallOnFlush) gate.await()
        }

        override fun flush() {
            if (stallOnFlush) gate.await()
        }
    }

    companion object {
        private const val ROOT_XML =
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:crypt=\"ocrclone\">" +
                "<d:response><d:href>/dav/Secret.vault/</d:href><d:propstat><d:prop>" +
                "<d:resourcetype><d:collection/></d:resourcetype><oc:fileid>vault</oc:fileid>" +
                "<d:getetag>\"root\"</d:getetag><crypt:integrity-id>proof-token</crypt:integrity-id>" +
                "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>" +
                "<d:response><d:href>/dav/Secret.vault/enc_bm90ZS5iaW4</d:href><d:propstat><d:prop>" +
                "<d:resourcetype/><oc:fileid>file</oc:fileid><d:getcontentlength>65601</d:getcontentlength>" +
                "<d:getetag>\"v1\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status>" +
                "</d:propstat></d:response></d:multistatus>"
    }
}
