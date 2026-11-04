package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
class VaultBoundaryLookupTest {
    private val cipher = VaultBoundaryTestCipher()
    private val server = MockWebServer()
    private val records = java.util.Collections.synchronizedMap(linkedMapOf<String, Record>())
    private val permit = AtomicBoolean(true)
    private val staging = Files.createTempDirectory("boundary-lookup-test").toFile()
    private lateinit var session: VaultSession
    private lateinit var endpoint: VaultBoundaryEndpoint
    private lateinit var account: AccountEntity
    private var currentAccount: AccountEntity? = null
    private var wrongRoot = false
    private var lateTail = ""
    private var afterEmptyProof: (() -> Unit)? = null
    private var reads = 0
    private var deletions = 0
    private var rejectDelete = false
    private var largestListing = 0

    @Before fun prepare() {
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = respond(request)
            }
        server.start()
        account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", false)
        currentAccount = account
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
        val access =
            VaultAccess(account, account.serverUrl, "Bearer synthetic", OkHttpClient(), permit::get, { currentAccount })
        session =
            VaultSession(
                VaultIdentity(account.id, account.serverUrl, "drive", "vault"),
                location,
                cipher,
                VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                access,
                { true },
                staging,
            )
        endpoint = VaultBoundaryEndpoint(session, location)
    }

    @After fun close() {
        session.close()
        server.shutdown()
        staging.deleteRecursively()
    }

    @Test fun `large parent target near end is read without a complete plaintext child list`() =
        runBlocking {
            val tiny = cipher.encryptBytes(byteArrayOf(1))
            repeat(10000) { number -> records["sibling-$number"] = Record("s-$number", "v1", tiny) }
            val original = "exact source".toByteArray()
            val expected = addFile("source.bin", original)
            val output = ByteArrayOutputStream()
            endpoint.read(expected, output)
            assertArrayEquals(original, output.toByteArray())
            assertTrue("Synthetic listing was $largestListing bytes", largestListing > 2 * 1024 * 1024)
            assertEquals(1, reads)
            assertEquals(0, session.issuedEntryCountForTesting())
            assertTrue(cipher.forks.all { it.closed.get() })
        }

    @Test fun `late duplicate rejects an earlier match before an operation token or read`() {
        val expected = addFile("source.bin", byteArrayOf(1))
        repeat(300) { addFile("sibling-$it", byteArrayOf(2)) }
        lateTail = response("duplicate", records.getValue("source.bin").copy())
        val failure =
            assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.requireUnchanged(expected) } }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(0, reads)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `wrong root and changed file versions never rebind a captured source`() {
        val expected = addFile("source.bin", byteArrayOf(1))
        records.getValue("source.bin").version = "v2"
        assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.requireUnchanged(expected) } }
        records.getValue("source.bin").version = "v1"
        wrongRoot = true
        assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.requireUnchanged(expected) } }
        assertEquals(0, reads)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `scoped exact read survives UI paging and unrelated same-session destination upload`() =
        runBlocking {
            val plain = "scoped source".toByteArray()
            val expected = addFile("source.bin", plain)
            var retained: VaultFolder? = null
            session.withBoundaryEntry(expected) { issued ->
                retained = issued
                session.openDirectory().use { it.page() }
                endpoint.write("", "target.bin", byteArrayOf(9).inputStream(), 1, null)
                val output = ByteArrayOutputStream()
                session.download(issued, output)
                assertArrayEquals(plain, output.toByteArray())
            }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { session.download(requireNotNull(retained), ByteArrayOutputStream()) }
            }
            session.openDirectory().close()
            assertEquals(0, session.issuedEntryCountForTesting())
            assertTrue(cipher.forks.all { it.closed.get() })
        }

    @Test fun `same-session boundary pipe larger than one block completes with independent monitored ciphers`() =
        runBlocking {
            withTimeout(20_000) {
                val plain = ByteArray(3 * 65536 + 37) { (it % 251).toByte() }
                val expected = addFile("source.bin", plain)
                BoundaryTransfer(
                    RuntimeEnvironment.getApplication(),
                ).execute(endpoint, expected, endpoint, "", false, "copy.bin")
                val output = ByteArrayOutputStream()
                cipher.decryptContent(records.getValue("copy.bin").bytes.inputStream(), output, Long.MAX_VALUE)
                assertArrayEquals(plain, output.toByteArray())
                assertTrue(records.containsKey("source.bin"))
                assertTrue(cipher.forks.size >= 3)
                assertTrue(cipher.forks.all { it.closed.get() })
            }
        }

    @Test fun `cancelling a stalled same-session consumer closes source fork and operation token`() =
        runBlocking {
            withTimeout(20_000) {
                val expected = addFile("source.bin", ByteArray(3 * 65536 + 37))
                val waiting = CompletableDeferred<Unit>()
                val stalled =
                    object : BoundaryEndpoint by endpoint {
                        override suspend fun write(
                            parent: String,
                            name: String,
                            source: InputStream,
                            size: Long,
                            mimeType: String?,
                        ): BoundaryEntry {
                            waiting.complete(Unit)
                            awaitCancellation()
                        }
                    }
                val task =
                    launch {
                        BoundaryTransfer(
                            RuntimeEnvironment.getApplication(),
                        ).execute(endpoint, expected, stalled, "", false, "copy.bin")
                    }
                waiting.await()
                task.cancelAndJoin()
                assertEquals(0, session.issuedEntryCountForTesting())
                assertTrue(cipher.forks.all { it.closed.get() })
                assertTrue(records.containsKey("source.bin"))
                assertTrue(!records.containsKey("copy.bin"))
            }
        }

    @Test fun `operation errors cancellation lock and account change always revoke scoped handles`() =
        runBlocking {
            val expected = addFile("source.bin", byteArrayOf(1))
            assertThrows(IllegalStateException::class.java) {
                runBlocking { session.withBoundaryEntry(expected) { error("synthetic operation error") } }
            }
            val entered = CompletableDeferred<Unit>()
            val task =
                async {
                    session.withBoundaryEntry(expected) {
                        entered.complete(Unit)
                        awaitCancellation()
                    }
                }
            entered.await()
            task.cancelAndJoin()
            session.withBoundaryEntry(expected) { issued ->
                permit.set(false)
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { session.download(issued, ByteArrayOutputStream()) } }
                permit.set(true)
                currentAccount = account.copy(displayName = "Replaced")
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { session.download(issued, ByteArrayOutputStream()) } }
            }
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    @Test fun `folder addition during empty proof prevents deleting its newer version`() {
        records["Folder"] = Record("folder-id", "before", ByteArray(0), true)
        afterEmptyProof = {
            records.getValue("Folder").version = "after"
            addFile("Folder/new.txt", byteArrayOf(1))
        }
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.delete(BoundaryEntry("folder-id", "Folder", "Folder", true, 0, "\"before\"")) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(0, deletions)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `unsupported content forks fail closed and remove admitted operation tokens`() {
        val expected = addFile("source.bin", byteArrayOf(1))
        cipher.refuseFork = true
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.read(expected, ByteArrayOutputStream()) }
            }
        assertEquals(OpenCloudError.Unsupported, failure.error)
        assertEquals(0, reads)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `a failed mutation consumes its scoped subject token without revoking another read`() =
        runBlocking {
            val expected = addFile("source.bin", byteArrayOf(1))
            val other = addFile("other.bin", byteArrayOf(2))
            session.withBoundaryEntry(other) { readLease ->
                session.withBoundaryEntry(expected) { subject ->
                    rejectDelete = true
                    assertThrows(eu.opencloud.android.next.core.network.TransferConflictException::class.java) {
                        runBlocking { session.delete(subject) }
                    }
                    assertThrows(OpenCloudException::class.java) { runBlocking { session.delete(subject) } }
                    val output = ByteArrayOutputStream()
                    session.download(readLease, output)
                    assertArrayEquals(byteArrayOf(2), output.toByteArray())
                }
            }
            assertEquals(1, deletions)
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    @Test fun `session close revokes independently registered operation handles immediately`() =
        runBlocking {
            val expected = addFile("source.bin", byteArrayOf(1))
            session.withBoundaryEntry(expected) { leased ->
                session.close()
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { session.download(leased, ByteArrayOutputStream()) } }
            }
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    @Test fun `a late invalid ciphertext size rejects an earlier successful name match`() {
        addFile("source.bin", byteArrayOf(1))
        repeat(300) { addFile("sibling-$it", byteArrayOf(2)) }
        records["late-corrupt"] = Record("late-corrupt-id", "v1", ByteArray(33))
        val failure =
            assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.containsName("", "source.bin") } }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(0, reads)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `root replacement after operation admission prevents the guarded read`() =
        runBlocking {
            val expected = addFile("source.bin", byteArrayOf(1))
            session.withBoundaryEntry(expected) { issued ->
                wrongRoot = true
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { session.download(issued, ByteArrayOutputStream()) } }
            }
            assertEquals(0, reads)
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    @Test fun `same identity caller alias cannot change admitted self and subtree placement paths`() =
        runBlocking {
            val alias =
                VaultBoundaryEndpoint(
                    session,
                    session.location.copy(
                        vaultPath = "Caller-Alias.vault",
                        title = "Caller title",
                        kind = VaultLocationKind.PERSONAL,
                    ),
                )
            val actual = "Secret.vault/${cipher.encryptPath("Folder")}"
            assertEquals(actual, alias.physicalPath("Folder"))
            val folder = BoundaryEntry("folder", "Folder", "Folder", true, 0, "\"v1\"")
            assertThrows(OpenCloudException::class.java) {
                runBlocking { requireBoundaryPlacement(endpoint, folder, alias, "", "Folder") }
            }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { requireBoundaryPlacement(endpoint, folder, alias, "Folder", "Nested") }
            }
            assertEquals(0, reads)
            assertEquals(0, deletions)
        }

    @Test fun `operation snapshot captures a large complete wire order independently of UI and writes`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val tiny = cipher.encryptBytes(byteArrayOf(1))
            repeat(10000) { number -> records["sibling-$number"] = Record("s-$number", "v1", tiny) }
            val expected = addFile("source.bin", byteArrayOf(2))
            endpoint.openDirectory(context, "").use { captured ->
                assertEquals(10001L, captured.totalCount)
                assertEquals("s-0", captured.page(0, 1).single().id)
                assertEquals(expected, captured.findById(expected.id))
                assertTrue(largestListing > 2 * 1024 * 1024)
                session.openDirectory().use { it.page(0, 1) }
                endpoint.write("", "target.bin", byteArrayOf(3).inputStream(), 1, null)
                assertEquals(expected, captured.findById(expected.id))
                assertEquals(null, captured.findById("created-target.bin"))
                assertEquals(2, captured.page(captured.totalCount - 2).size)
                assertEquals(10001L, captured.totalCount)
            }
        }

    @Test fun `late duplicate prevents a production operation snapshot from being returned`() {
        addFile("source.bin", byteArrayOf(1))
        repeat(300) { addFile("sibling-$it", byteArrayOf(2)) }
        lateTail = response("duplicate", records.getValue("source.bin").copy())
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDirectory(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(0, session.issuedEntryCountForTesting())
        assertEquals(0, reads)
    }

    @Test fun `name reservations capture a large parent once and never read HTTP for collision candidates`() =
        runBlocking {
            val tiny = cipher.encryptBytes(byteArrayOf(1))
            repeat(10000) { number -> records["sibling-$number"] = Record("s-$number", "v1", tiny) }
            endpoint.openNameIndex(RuntimeEnvironment.getApplication(), "").use { names ->
                val capturedRequests = server.requestCount
                assertTrue(largestListing > 2 * 1024 * 1024)
                repeat(500) { number -> assertTrue(!names.reserve("sibling-$number")) }
                assertTrue(names.reserve("new-name.txt"))
                assertTrue(!names.reserve("new-name.txt"))
                assertEquals(capturedRequests, server.requestCount)
            }
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    @Test fun `late invalid metadata prevents a production name index from being published`() {
        addFile("source.bin", byteArrayOf(1))
        repeat(257) { addFile("sibling-$it", byteArrayOf(2)) }
        records["late-corrupt"] = Record("late-corrupt-id", "v1", ByteArray(33))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openNameIndex(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(0, reads)
        assertEquals(0, session.issuedEntryCountForTesting())
    }

    @Test fun `folder chooser pages keep the source UI lease and close independently`() =
        runBlocking {
            val plain = byteArrayOf(7, 8, 9)
            addFile("source.bin", plain)
            repeat(301) { number ->
                records["folder-${number.toString().padStart(3, '0')}"] =
                    Record("folder-$number", "v1", ByteArray(0), true)
            }
            session.openDirectory().use { sourcePage ->
                val source = sourcePage.page(301).single()
                endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "").use { folders ->
                    assertEquals(301L, folders.totalCount)
                    assertEquals(128, folders.page().size)
                    assertEquals("folder-300", folders.page(256).last().name)
                    assertTrue(folders.page(301).isEmpty())
                    val output = ByteArrayOutputStream()
                    session.download(source, output)
                    assertArrayEquals(plain, output.toByteArray())
                }
                val output = ByteArrayOutputStream()
                session.download(source, output)
                assertArrayEquals(plain, output.toByteArray())
            }
        }

    @Test fun `ignored late file still requires valid ciphertext before folder chooser publication`() {
        records["early-folder"] = Record("folder", "v1", ByteArray(0), true)
        records["late-file"] = Record("late", "v1", ByteArray(33))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(0, session.issuedEntryCountForTesting())
        assertEquals(0, reads)
    }

    @Test fun `folder chooser rejects wrong root before capture and lock before later pages`() =
        runBlocking {
            records["folder"] = Record("folder", "v1", ByteArray(0), true)
            wrongRoot = true
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "") }
            }
            wrongRoot = false
            endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "").use { folders ->
                permit.set(false)
                assertThrows(OpenCloudException::class.java) { runBlocking { folders.page() } }
            }
            assertEquals(0, session.issuedEntryCountForTesting())
        }

    private fun addFile(
        path: String,
        plain: ByteArray,
    ): BoundaryEntry {
        val record = Record("id-$path", "v1", cipher.encryptBytes(plain))
        records[path] = record
        return BoundaryEntry(record.id, path, path.substringAfterLast('/'), false, plain.size.toLong(), "\"v1\"")
    }

    @Suppress("ReturnCount") // Fixture routing keeps each HTTP failure status explicit.
    private fun respond(request: RecordedRequest): MockResponse {
        val encoded =
            request.path
                .orEmpty()
                .substringAfter("/dav/Secret.vault", "")
                .trim('/')
        val path = if (encoded.isEmpty()) "" else cipher.decryptPath(encoded)
        return when (request.method) {
            "PROPFIND" -> listing(path, request.getHeader("Depth") == "1")
            "GET" -> {
                reads++
                val record = records[path] ?: return MockResponse().setResponseCode(404)
                if (request.getHeader("If-Match") != "\"${record.version}\"") return MockResponse().setResponseCode(412)
                MockResponse().setHeader("ETag", "\"${record.version}\"").setBody(Buffer().write(record.bytes))
            }
            "PUT" -> {
                if (records.containsKey(path)) return MockResponse().setResponseCode(412)
                assertEquals("*", request.getHeader("If-None-Match"))
                records[path] = Record("created-$path", "new", request.body.readByteArray())
                MockResponse().setResponseCode(201)
            }
            "DELETE" -> {
                deletions++
                if (rejectDelete) return MockResponse().setResponseCode(412)
                val record = records[path] ?: return MockResponse().setResponseCode(404)
                if (request.getHeader("If-Match") != "\"${record.version}\"") return MockResponse().setResponseCode(412)
                records.remove(path)
                MockResponse().setResponseCode(204)
            }
            else -> MockResponse().setResponseCode(400)
        }
    }

    private fun listing(
        path: String,
        children: Boolean,
    ): MockResponse {
        val self =
            if (path.isEmpty()) {
                Record(if (wrongRoot) "wrong-root" else "vault", "root", ByteArray(0), true)
            } else {
                records[path] ?: return MockResponse().setResponseCode(404)
            }
        val childRows =
            if (children) {
                synchronized(records) {
                    records.entries.filter { it.key.substringBeforeLast('/', "") == path }.map {
                        it.key to
                            it.value.copy()
                    }
                }
            } else {
                emptyList()
            }
        val xml =
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:crypt=\"ocrclone\">" +
                response(path, self) + childRows.joinToString("") { response(it.first, it.second) } +
                (if (children && path.isEmpty()) lateTail else "") + "</d:multistatus>"
        largestListing = maxOf(largestListing, xml.length)
        if (children &&
            path == "Folder" &&
            childRows.isEmpty()
        ) {
            afterEmptyProof?.also { afterEmptyProof = null }?.invoke()
        }
        return MockResponse().setResponseCode(207).setBody(xml)
    }

    private fun response(
        path: String,
        record: Record,
    ): String {
        val rawPath = if (path.isEmpty()) "" else "/${cipher.encryptPath(path)}"
        val href = "/dav/Secret.vault$rawPath" + if (record.folder) "/" else ""
        val collection = if (record.folder) "<d:collection/>" else ""
        val proof = if (path.isEmpty()) "<crypt:integrity-id>proof-token</crypt:integrity-id>" else ""
        return "<d:response><d:href>$href</d:href><d:propstat><d:prop><d:resourcetype>$collection</d:resourcetype>" +
            "<d:getcontentlength>${record.bytes.size}</d:getcontentlength>" +
            "<d:getetag>\"${record.version}\"</d:getetag><oc:fileid>${record.id}</oc:fileid>$proof</d:prop>" +
            "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    }

    private data class Record(
        val id: String,
        var version: String,
        val bytes: ByteArray,
        val folder: Boolean = false,
    )
}
