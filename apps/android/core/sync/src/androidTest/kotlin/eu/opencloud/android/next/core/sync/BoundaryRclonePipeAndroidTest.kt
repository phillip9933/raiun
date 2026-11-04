package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Real native rclone streams; only HTTP and account ownership are synthetic. No owner service is contacted. */
@RunWith(AndroidJUnit4::class)
class BoundaryRclonePipeAndroidTest {
    @Test fun sameSessionNativeContentForksDrainMoreThanOnePipeBufferAndVerifyRoundTrip() =
        bounded {
            Fixture().use { fixture ->
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { fixture.endpoint.requireUnchanged(fixture.source.copy(mimeType = "text/plain")) }
                }
                runBlocking {
                    fixture.endpoint.openDirectory(fixture.context, "").use { snapshot ->
                        assertEquals(1L, snapshot.totalCount)
                        assertEquals(listOf(fixture.source), snapshot.page())
                        assertEquals(fixture.source, snapshot.findById(fixture.source.id))
                    }
                    fixture.endpoint.openNameIndex(fixture.context, "").use { names ->
                        assertFalse(names.reserve(fixture.source.name))
                        assertTrue(names.reserve("copy.txt"))
                        assertFalse(names.reserve("copy.txt"))
                    }
                    fixture.endpoint.openDestinationFolders(fixture.context, "").use { folders ->
                        assertEquals(0L, folders.totalCount)
                        assertTrue(folders.page().isEmpty())
                    }
                    BoundaryTransfer(
                        fixture.context,
                    ).execute(fixture.endpoint, fixture.source, fixture.endpoint, "", false, "copy.txt")
                }
                assertTrue(fixture.plain.size > 64 * 1024)
                val copied = requireNotNull(fixture.http.contents[fixture.copyName])
                RcloneVaultCipher.fromKeyMaterial(fixture.material).use { cipher ->
                    val decoded = ByteArrayOutputStream()
                    cipher.decryptContent(copied.inputStream(), decoded, fixture.plain.size.toLong())
                    assertArrayEquals(fixture.plain, decoded.toByteArray())
                }
                assertEquals(0, fixture.activeForks.get())
                assertTrue(fixture.forksCreated.get() >= 3) // Source decrypt, target encrypt, readback decrypt.
                fixture.session.close()
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { fixture.endpoint.requireUnchanged(fixture.source) } }
            }
        }

    @Test fun cancellationOfStalledSameSessionNativePipeClosesForksAndRefusesClosedSession() =
        bounded {
            Fixture(stallPut = true).use { fixture ->
                val outcome = AtomicReference<Throwable?>()
                runBlocking {
                    val copying =
                        launch(Dispatchers.IO) {
                            try {
                                BoundaryTransfer(
                                    fixture.context,
                                ).execute(fixture.endpoint, fixture.source, fixture.endpoint, "", false, "copy.txt")
                            } catch (cancelled: CancellationException) {
                                outcome.set(cancelled)
                            } catch (refused: OpenCloudException) {
                                outcome.set(refused)
                            }
                        }
                    assertTrue(
                        "Expected real PUT before cancellation",
                        fixture.http.putStarted.await(5, TimeUnit.SECONDS),
                    )
                    fixture.allowed = false
                    copying.cancel()
                    fixture.session.cancelBoundaryRequests()
                    fixture.http.releasePut.countDown()
                    copying.join()
                }
                // The live guard can observe revocation before cancel() reaches the child.
                // Both refuse this transfer; every other domain error or normal return must fail.
                when (val failure = outcome.get()) {
                    is CancellationException -> Unit
                    is OpenCloudException -> assertEquals(OpenCloudError.AccessDenied, failure.error)
                    else -> throw AssertionError("Deliberately revoked transfer unexpectedly completed")
                }
                assertEquals(0, fixture.activeForks.get())
                assertEquals(0, fixture.http.deletes.get())
                assertTrue(fixture.http.contents.containsKey(fixture.sourceName))
                fixture.allowed = false
                fixture.session.close()
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { fixture.endpoint.read(fixture.source, ByteArrayOutputStream()) }
                }
                assertEquals(0, fixture.activeForks.get())
            }
        }

    /** Daemon watchdog plus bounded HTTP timeouts prevents a broken cipher monitor from hanging instrumentation. */
    private fun bounded(block: () -> Unit) {
        val failure = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        Thread {
            try {
                block()
            } catch (error: Throwable) {
                failure.set(error)
            } finally {
                done.countDown()
            }
        }.apply {
            isDaemon = true
            name = "native-boundary-test"
            start()
        }
        assertTrue("Native shared-session transfer must terminate within 20 seconds", done.await(20, TimeUnit.SECONDS))
        failure.get()?.let { throw AssertionError("Native boundary regression failed", it) }
    }

    private class Fixture(
        stallPut: Boolean = false,
    ) : AutoCloseable {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val material = ByteArray(80) { (it + 11).toByte() }
        val plain = ByteArray(512 * 1024 + 37) { (it * 17).toByte() }
        val activeForks = AtomicInteger()
        val forksCreated = AtomicInteger()

        @Volatile var allowed = true
        private val spool = File(context.cacheDir, "native-boundary-${UUID.randomUUID()}").apply { check(mkdirs()) }
        private val real = RcloneVaultCipher.fromKeyMaterial(material)
        val sourceName = real.encryptName("source.txt")
        val copyName = real.encryptName("copy.txt")
        val http = LocalDav(real.createIntegrityToken(), sourceName, stallPut)
        val session: VaultSession
        val endpoint: VaultBoundaryEndpoint
        val source =
            BoundaryEntry(
                "source-id",
                "source.txt",
                "source.txt",
                false,
                plain.size.toLong(),
                "\"source-tag\"",
                null, // Vault DAV metadata retains content type only as a vault marker, not a plaintext MIME.
            )

        init {
            val encrypted = ByteArrayOutputStream()
            real.encryptContent(plain.inputStream(), encrypted, plain.size.toLong())
            http.contents[sourceName] = encrypted.toByteArray()
            val server = "http://127.0.0.1:${http.port}/"
            check(java.net.URI(server).host == "127.0.0.1")
            val account = AccountEntity("synthetic-${UUID.randomUUID()}", server, "user", "User", "BASIC", false)
            val location =
                VaultLocation(
                    account.id,
                    "Secret.vault",
                    VaultLocationKind.FOLDER_VAULT,
                    "drive",
                    "vault-id",
                    "root-id",
                    server,
                    server + "dav/",
                    "Secret.vault",
                    true,
                )
            val client =
                OkHttpClient
                    .Builder()
                    .callTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(3, TimeUnit.SECONDS)
                    .writeTimeout(3, TimeUnit.SECONDS)
                    .build()
            val delegate = real.asVaultCipher()
            val tracked =
                object : VaultCipherEngine by delegate {
                    override fun forkForContent(): VaultCipherEngine {
                        val fork = delegate.forkForContent()
                        forksCreated.incrementAndGet()
                        activeForks.incrementAndGet()
                        return object : VaultCipherEngine by fork {
                            private var closed = false

                            override fun close() {
                                if (!closed) {
                                    closed = true
                                    try {
                                        fork.close()
                                    } finally {
                                        activeForks.decrementAndGet()
                                    }
                                }
                            }
                        }
                    }
                }
            session =
                VaultSession(
                    VaultIdentity(account.id, server, "drive", "vault-id"),
                    location,
                    tracked,
                    VaultDavClient(client, endpoints = EndpointPolicy(true)),
                    VaultAccess(
                        account,
                        server,
                        "Bearer synthetic",
                        client,
                        { allowed },
                        { if (allowed) account else null },
                    ),
                    { allowed },
                    spool,
                )
            endpoint = VaultBoundaryEndpoint(session, location)
            // Check every independently specified descriptor field before exercising the concurrent pipe.
            runBlocking { assertEquals(source, session.list().single().asBoundaryEntry()) }
        }

        override fun close() {
            allowed = false
            http.close()
            session.close()
            material.fill(0)
            plain.fill(0)
            spool.deleteRecursively()
        }
    }

    private class LocalDav(
        private val proof: String,
        private val sourceName: String,
        private val stallPut: Boolean,
    ) : AutoCloseable {
        private val listener = ServerSocket(0, 16, java.net.InetAddress.getByName("127.0.0.1"))
        private val sockets = ConcurrentHashMap.newKeySet<Socket>()
        val port get() = listener.localPort
        val contents = ConcurrentHashMap<String, ByteArray>()
        val putStarted = CountDownLatch(1)
        val releasePut = CountDownLatch(1)
        val deletes = AtomicInteger()

        init {
            Thread {
                while (!listener.isClosed) {
                    val socket =
                        try {
                            listener.accept()
                        } catch (_: java.io.IOException) {
                            break
                        }
                    sockets += socket
                    Thread {
                        try {
                            socket.soTimeout = 3_000
                            handle(socket)
                        } catch (
                            _: java.io.IOException,
                        ) {
                        } finally {
                            sockets -= socket
                            socket.close()
                        }
                    }.apply {
                        isDaemon = true
                        start()
                    }
                }
            }.apply {
                isDaemon = true
                start()
            }
        }

        private fun handle(socket: Socket) {
            val input = socket.getInputStream()
            val request = line(input).split(' ')
            if (request.size < 2) return
            val headers = mutableMapOf<String, String>()
            while (true) {
                val next = line(input)
                if (next.isEmpty()) break
                headers[next.substringBefore(':').lowercase()] = next.substringAfter(':').trim()
            }
            val path = request[1].substringBefore('?')
            val name = path.trimEnd('/').substringAfterLast('/')
            if (request[0] != "PUT") {
                // Consume PROPFIND XML before closing the connection, avoiding a TCP reset with unread input.
                val remaining = headers["content-length"]?.toInt() ?: 0
                check(remaining in 0..65_536)
                repeat(remaining) { if (input.read() < 0) throw java.io.IOException("Interrupted request") }
            }
            when (request[0]) {
                "PROPFIND" -> respond(socket, 207, listing(headers["depth"] == "1").toByteArray())
                "GET" -> {
                    val bytes = contents[name]
                    if (bytes == null) respond(socket, 404, byteArrayOf()) else respond(socket, 200, bytes, etag(name))
                }
                "PUT" -> {
                    putStarted.countDown()
                    if (stallPut) releasePut.await(5, TimeUnit.SECONDS)
                    val size = headers["content-length"]?.toInt() ?: throw java.io.IOException("Missing length")
                    val body = ByteArray(size)
                    var offset = 0
                    while (offset < size) {
                        val count = input.read(body, offset, size - offset)
                        if (count < 0) throw java.io.IOException("Interrupted body")
                        offset += count
                    }
                    if (contents.putIfAbsent(name, body) != null) {
                        respond(socket, 412, byteArrayOf())
                    } else {
                        respond(socket, 201, byteArrayOf())
                    }
                }
                "DELETE" -> {
                    deletes.incrementAndGet()
                    respond(socket, 403, byteArrayOf())
                }
                else -> respond(socket, 405, byteArrayOf())
            }
        }

        private fun listing(children: Boolean): String {
            val root = entry("/dav/Secret.vault/", "vault-id", "Secret.vault", true, 0, proof)
            val files =
                if (children) {
                    contents.entries.joinToString("") { (name, bytes) ->
                        entry(
                            "/dav/Secret.vault/$name",
                            if (name ==
                                sourceName
                            ) {
                                "source-id"
                            } else {
                                "copy-id"
                            },
                            name,
                            false,
                            bytes.size,
                            null,
                        )
                    }
                } else {
                    ""
                }
            return "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" " +
                "xmlns:ocrclone=\"ocrclone\">$root$files</d:multistatus>"
        }

        private fun entry(
            path: String,
            id: String,
            name: String,
            folder: Boolean,
            size: Int,
            token: String?,
        ): String =
            "<d:response><d:href>$path</d:href><d:propstat><d:prop>" +
                "<d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype>" +
                "<d:getcontentlength>$size</d:getcontentlength><d:getcontenttype>text/plain</d:getcontenttype>" +
                "<d:getetag>${if (folder) {
                    "\"root-tag\""
                } else {
                    etag(
                        name,
                    )
                }}</d:getetag>" +
                "<oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>${token?.let {
                    "<ocrclone:integrity-id>$it</ocrclone:integrity-id>"
                }.orEmpty()}" +
                "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

        private fun etag(name: String) = if (name == sourceName) "\"source-tag\"" else "\"copy-tag\""

        private fun respond(
            socket: Socket,
            code: Int,
            body: ByteArray,
            version: String? = null,
        ) {
            val head =
                "HTTP/1.1 $code Test\r\nContent-Length: ${body.size}\r\nConnection: close\r\n" +
                    (version?.let { "ETag: $it\r\n" } ?: "") + "\r\n"
            socket.getOutputStream().apply {
                write(head.toByteArray())
                write(body)
                flush()
            }
        }

        private fun line(input: InputStream): String {
            val bytes = ByteArrayOutputStream()
            while (bytes.size() < 16_384) {
                val byte = input.read()
                if (byte == -1 || byte == 10) break
                if (byte != 13) bytes.write(byte)
            }
            return bytes.toString("US-ASCII")
        }

        override fun close() {
            releasePut.countDown()
            listener.close()
            sockets.forEach { runCatching { it.close() } }
        }
    }
}
