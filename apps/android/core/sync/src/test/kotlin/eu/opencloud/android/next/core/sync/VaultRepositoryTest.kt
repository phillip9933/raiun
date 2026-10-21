package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
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
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
// Shared in-memory Room + DAV fixtures keep account and malformed-protocol cases deterministic.
@Suppress("LargeClass")
class VaultRepositoryTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var account: AccountEntity

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        store = FileBrowserStore(database)
        account = AccountEntity("account", server.url("/").toString().trimEnd('/'), "user", "User", "BASIC", false)
        runBlocking { database.accountDao().upsert(account) }
    }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
    }

    @Test
    fun `discovery binds account and uses only authorized graph drives`() =
        runTest {
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    "/dav/files/",
                    "root",
                    "files",
                    true,
                    listOf(entry("/dav/files/Secret.vault", "vault-root", "Secret.vault", true)),
                ),
            )
            val events = mutableListOf<String>()
            val repository = repository(events)

            val locations = repository.locations(account.id)

            assertEquals(listOf(VaultLocationKind.PERSONAL, VaultLocationKind.FOLDER_VAULT), locations.map { it.kind })
            val vault = locations.last()
            assertEquals(account.id, vault.accountId)
            assertEquals("drive", vault.driveId)
            assertEquals("vault-root", vault.remoteVaultId)
            assertEquals("root", vault.sourceRootId)
            assertEquals("Secret.vault", vault.vaultPath)
            assertEquals(listOf("permit", "authorization", "client"), events)
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)
        }

    @Test
    fun `Graph vault Space accepts full DAV root ID through discovery unlock and revalidation`() =
        runTest {
            val graphRoot = "storage\$space"
            val davRoot = "$graphRoot!space"
            val rootPath = "/dav/spaces/$graphRoot/"
            server.enqueue(graphVaultPage(graphRoot, "dav/spaces/$graphRoot/"))
            server.enqueue(davSpaceRootListing(rootPath, davRoot))
            val repository = repository(cipher = FakeCipher())

            val location = repository.locations(account.id).single()

            assertEquals(VaultLocationKind.SPACE_VAULT, location.kind)
            assertEquals("vault-drive", location.driveId)
            assertEquals(davRoot, location.remoteVaultId)
            assertEquals(graphRoot, location.sourceRootId)
            assertEquals("", location.vaultPath)
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)

            server.enqueue(graphVaultPage(graphRoot, "dav/spaces/$graphRoot/"))
            server.enqueue(
                davSpaceRootListing(
                    rootPath,
                    davRoot,
                    listOf(entry("${rootPath}cipher", "file-id", "cipher", false, 49)),
                ),
            )
            server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(49) { it.toByte() })))
            val engine = FakeCipher()

            val session = repository(cipher = engine).unlock(account.id, location, password = charArrayOf('p'))
            try {
                assertEquals(VaultLocationKind.SPACE_VAULT, session.location.kind)
                assertEquals("vault-drive", session.identity.driveId)
                assertEquals(davRoot, session.identity.remoteVaultId)
                assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
                assertEquals("PROPFIND", server.takeRequest().method)
                val proof = server.takeRequest()
                assertEquals("GET", proof.method)
                assertEquals("bytes=0-65583", proof.getHeader("Range"))

                server.enqueue(davSpaceRootListing(rootPath, davRoot))
                server.enqueue(davSpaceRootListing(rootPath, davRoot))
                server.enqueue(davSpaceRootListing(rootPath, davRoot))
                assertTrue(session.list().isEmpty())
            } finally {
                session.close()
            }
            assertTrue(engine.closed.get())
        }

    @Test
    fun `Graph vault Space rejects another opaque ID or storage`() =
        runTest {
            val graphRoot = "storage\$space"
            for (davRoot in listOf("$graphRoot!other", "otherStorage\$space!space")) {
                server.enqueue(graphVaultPage(graphRoot, "dav/spaces/$graphRoot/"))
                server.enqueue(davSpaceRootListing("/dav/spaces/$graphRoot/", davRoot))
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository().locations(account.id) }
                }
            }
            assertEquals(4, server.requestCount)
        }

    @Test
    fun `ordinary folder discovery returns only directories with child relative paths`() =
        runTest {
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    "/dav/files/",
                    "root",
                    "files",
                    true,
                    listOf(
                        entry("/dav/files/folder", "folder-id", "folder", true, 21),
                        entry("/dav/files/document.txt", "file-id", "document.txt", false, 10),
                    ),
                ),
            )
            val repository = repository()
            val source =
                VaultLocation(
                    account.id,
                    "Personal",
                    VaultLocationKind.PERSONAL,
                    "drive",
                    "root",
                    "root",
                    server.url("/").toString(),
                    server.url("dav/files/").toString(),
                    "",
                    false,
                )

            val folders = repository.folders(account.id, source)

            assertEquals(1, folders.size)
            assertEquals("folder", folders.single().path)
            assertEquals("folder", folders.single().rawName)
            assertEquals(21L, folders.single().size)
            assertTrue(folders.single().isFolder)
        }

    @Test
    fun `nested vault unlock falls back to authenticated nonempty file proof`() =
        runTest {
            val vaultPath = "parent/Secret.vault"
            val rootPath = "/dav/files/$vaultPath"
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 49)),
                ),
            )
            server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(49) { it.toByte() })))
            val engine = FakeCipher()
            val repository = repository(cipher = engine)
            val source = personalLocation()

            val session = repository.unlock(account.id, source, vaultPath, charArrayOf('p', 'a', 's', 's'))
            try {
                assertEquals("vault-id", session.identity.remoteVaultId)
                assertEquals("parent/Secret.vault", session.location.vaultPath)
                assertEquals(VaultLocationKind.FOLDER_VAULT, session.location.kind)
                val graphRequest = server.takeRequest()
                assertEquals("/graph/v1.0/me/drives", graphRequest.path)
                val listingRequest = server.takeRequest()
                assertEquals("PROPFIND", listingRequest.method)
                assertEquals("/dav/files/parent/Secret.vault", listingRequest.path)
                val proofRequest = server.takeRequest()
                assertEquals("GET", proofRequest.method)
                assertEquals("bytes=0-65583", proofRequest.getHeader("Range"))
            } finally {
                session.close()
            }
            assertTrue(engine.closed.get())
        }

    @Test
    fun `missing proof and only empty file stays unproven without a ciphertext read`() =
        runTest {
            val vaultPath = "parent/Secret.vault"
            val rootPath = "/dav/files/$vaultPath"
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$rootPath/empty", "empty-id", "empty", false, 32)),
                ),
            )
            val engine = FakeCipher()
            val failure =
                assertThrows(VaultUnlockException::class.java) {
                    runBlocking {
                        repository(
                            cipher = engine,
                        ).unlock(account.id, personalLocation(), vaultPath, charArrayOf('x'))
                    }
                }
            assertEquals(VaultUnlockFailure.PASSWORD_NOT_PROVEN, failure.failure)
            assertEquals(2, server.requestCount)
            assertTrue(engine.closed.get())
        }

    @Test
    fun `revoked DAV access during missing-token proof remains an HTTP error`() =
        runTest {
            val vaultPath = "parent/Secret.vault"
            val rootPath = "/dav/files/$vaultPath"
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 49)),
                ),
            )
            server.enqueue(MockResponse().setResponseCode(401))
            val engine = FakeCipher()

            val failure =
                assertThrows(TransferHttpException::class.java) {
                    runBlocking {
                        repository(cipher = engine).unlock(
                            account.id,
                            personalLocation(),
                            vaultPath,
                            charArrayOf('p'),
                        )
                    }
                }

            assertEquals(401, failure.statusCode)
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)
            val proofRequest = server.takeRequest()
            assertEquals("GET", proofRequest.method)
            assertEquals("bytes=0-65583", proofRequest.getHeader("Range"))
            assertTrue(engine.closed.get())
        }

    @Test
    fun `inactive account and cross-account location fail before authorization or network`() =
        runTest {
            val events = mutableListOf<String>()
            val repository = repository(events)
            val otherAccount = personalLocation().copy(accountId = "other")
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.folders(account.id, otherAccount) }
            }
            assertTrue(events.isEmpty())
            assertEquals(0, server.requestCount)

            database.accountDao().upsert(account.copy(isActive = false))
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.locations(account.id) }
            }
            assertTrue(events.isEmpty())
            assertEquals(0, server.requestCount)
        }

    @Test
    fun `preview is scoped to session entry and revalidates stable vault root`() =
        runTest {
            val rootPath = "/dav/files/parent/Secret.vault"
            val dav = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 4)),
                ),
            )
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            server.enqueue(MockResponse().setBody(Buffer().write(byteArrayOf(1, 2, 3, 4))))
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            val engine = FakeCipher()
            val session = session(dav, engine)
            try {
                val child = session.list().single()
                val plaintext = session.preview(child)
                assertArrayEquals("preview".toByteArray(), plaintext)
                assertEquals(6, server.requestCount)
                assertTrue(server.takeRequest().method == "PROPFIND") // before listing
                assertTrue(server.takeRequest().method == "PROPFIND") // listing
                assertTrue(server.takeRequest().method == "PROPFIND") // after listing
                assertTrue(server.takeRequest().method == "PROPFIND") // before preview
                val get = server.takeRequest()
                assertEquals("GET", get.method)
                assertEquals("/dav/files/parent/Secret.vault/cipher", get.path)
                assertEquals("PROPFIND", server.takeRequest().method) // root checked after decrypt
            } finally {
                session.close()
            }
            assertTrue(engine.closed.get())
        }

    @Test
    fun `preview rejects mutated or out of vault entries before network access`() =
        runTest {
            val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), FakeCipher())
            try {
                val forged =
                    VaultFolder(
                        "id",
                        "secret",
                        "cipher",
                        "secret",
                        "elsewhere/cipher",
                        false,
                        4,
                        null,
                        leaseId = "fake-token",
                    )
                assertThrows(OpenCloudException::class.java) { runBlocking { session.preview(forged) } }
                assertEquals(0, server.requestCount)
            } finally {
                session.close()
            }
        }

    @Test
    fun `preview refuses a vault whose stable remote root ID changed`() =
        runTest {
            val rootPath = "/dav/files/parent/Secret.vault"
            val dav = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 4)),
                ),
            )
            server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
            server.enqueue(davListing(rootPath, "replacement-id", "Secret.vault", true))
            val session = session(dav, FakeCipher())
            try {
                val item = session.list().single()
                assertThrows(OpenCloudException::class.java) { runBlocking { session.preview(item) } }
                assertEquals(4, server.requestCount)
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("PROPFIND", server.takeRequest().method)
            } finally {
                session.close()
            }
        }

    @Test
    fun `cancellation during preview wipes buffered plaintext`() {
        val rootPath = "/dav/files/parent/Secret.vault"
        val dav = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        server.enqueue(
            davListing(
                rootPath,
                "vault-id",
                "Secret.vault",
                true,
                listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 4)),
            ),
        )
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        server.enqueue(MockResponse().setBody(Buffer().write(byteArrayOf(1, 2, 3, 4))))
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        val job = SupervisorJob()
        val engine = FakeCipher(onDecrypt = { job.cancel() })
        val session = session(dav, engine)
        val scope = kotlinx.coroutines.CoroutineScope(job + Dispatchers.Unconfined)
        try {
            val listed = runBlocking { session.list().single() }
            val request = scope.async { session.preview(listed) }
            assertThrows(CancellationException::class.java) { runBlocking { request.await() } }
            val buffered = engine.lastOutput as? ByteArrayOutputStream
            assertEquals(0, buffered?.size())
        } finally {
            scope.cancel()
            session.close()
        }
    }

    @Test
    fun `cancelled list removes its undelivered entries`() {
        val rootPath = "/dav/files/parent/Secret.vault"
        val dav = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        server.enqueue(
            davListing(
                rootPath,
                "vault-id",
                "Secret.vault",
                true,
                listOf(entry("$rootPath/cipher", "file-id", "cipher", false, 49)),
            ),
        )
        server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true))
        val job = SupervisorJob()
        var generationChecks = 0
        val engine = FakeCipher()
        val session =
            session(
                dav,
                engine,
                generationIsCurrent = {
                    generationChecks += 1
                    // The eighth check is the final guard immediately before registry publication.
                    if (generationChecks == 8) job.cancel()
                    true
                },
            )
        val scope = kotlinx.coroutines.CoroutineScope(job + Dispatchers.Unconfined)
        try {
            val request = scope.async { session.list() }
            assertThrows(CancellationException::class.java) { runBlocking { request.await() } }
            assertEquals(8, generationChecks)
            assertEquals(0, session.issuedEntryCountForTesting())
        } finally {
            scope.cancel()
            session.close()
        }
        assertTrue(engine.closed.get())
    }

    @Test
    fun `transfer handoff path stays relative to vault and revalidates identity`() {
        val rootPath = "/dav/files/parent/Secret.vault"
        val dav = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        repeat(4) { server.enqueue(davListing(rootPath, "vault-id", "Secret.vault", true)) }
        val session = session(dav, FakeCipher())
        try {
            val encoded = runBlocking { session.encodeDirectoryPath("photos/2026") }
            assertEquals("photos/2026", encoded)
            val decoded = runBlocking { session.decodeDirectoryPath(encoded) }
            assertEquals("photos/2026", decoded)
            repeat(4) {
                val request = server.takeRequest()
                assertEquals("PROPFIND", request.method)
                assertEquals(rootPath, request.requestUrl?.encodedPath)
            }
        } finally {
            session.close()
        }
    }

    @Test
    fun `cancellation during verified key export wipes defensive copy`() {
        val job = SupervisorJob()
        val engine = FakeCipher(onExport = { job.cancel() })
        val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), engine)
        val scope = kotlinx.coroutines.CoroutineScope(job + Dispatchers.Unconfined)
        try {
            val request = scope.async { session.exportVerifiedKeyMaterial() }
            assertThrows(CancellationException::class.java) { runBlocking { request.await() } }
            assertArrayEquals(ByteArray(80), requireNotNull(engine.exported))
        } finally {
            scope.cancel()
            session.close()
        }
    }

    private fun repository(
        events: MutableList<String> = mutableListOf(),
        cipher: FakeCipher = FakeCipher(),
    ): VaultRepository =
        VaultRepository(
            store = store,
            authorizationFor = {
                events += "authorization"
                "Bearer test"
            },
            clientFor = {
                events += "client"
                OkHttpClient()
            },
            endpointPolicy = EndpointPolicy(true),
            permitFor = {
                events += "permit";
                { true }
            },
            cipherFactories = VaultCipherFactories(password = { cipher }, keyMaterial = { cipher }),
        )

    private fun personalLocation(): VaultLocation =
        VaultLocation(
            account.id,
            "Personal",
            VaultLocationKind.PERSONAL,
            "drive",
            "root",
            "root",
            server.url("/").toString(),
            server.url("dav/files/").toString(),
            "",
            false,
        )

    private fun session(
        dav: VaultDavClient,
        engine: FakeCipher,
        vaultPath: String = "parent/Secret.vault",
        generationIsCurrent: () -> Boolean = { true },
    ): VaultSession {
        val vaultLocation =
            VaultLocation(
                account.id,
                vaultPath.substringAfterLast('/'),
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault-id",
                "root",
                account.serverUrl,
                server.url("dav/files/").toString(),
                vaultPath,
                true,
            )
        val access =
            VaultAccess(
                account,
                account.serverUrl,
                "Bearer test",
                OkHttpClient(),
                { true },
                { store.account(account.id) },
            )
        return VaultSession(
            VaultIdentity(account.id, account.serverUrl, "drive", "vault-id"),
            vaultLocation,
            engine,
            dav,
            access,
            generationIsCurrent,
        )
    }

    private fun graphPage(): MockResponse {
        val webDavUrl = server.url("dav/files/")
        return MockResponse().setBody(
            """{"value":[{"id":"drive","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"$webDavUrl"}}]}""",
        )
    }

    private fun graphVaultPage(
        rootId: String = "space-root",
        webDavPath: String = "dav/vault/",
    ): MockResponse {
        val webDavUrl = server.url(webDavPath)
        return MockResponse().setBody(
            """{"value":[{"id":"vault-drive","name":"Archive","driveType":"project","@libre.graph.contentType":"application/vnd.opencloud.vault","root":{"id":"$rootId","webDavUrl":"$webDavUrl"}}]}""",
        )
    }

    private fun davSpaceRootListing(
        path: String,
        rootId: String,
        children: List<String> = emptyList(),
    ): MockResponse =
        MockResponse().setResponseCode(207).setBody(
            """
            <?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">
            <d:response><d:href>$path</d:href><d:propstat><d:prop>
            <oc:fileid>$rootId</oc:fileid><oc:id>$rootId</oc:id><oc:name>Archive</oc:name><oc:size>0</oc:size>
            <d:resourcetype><d:collection/></d:resourcetype>
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
            <d:propstat><d:prop><d:getcontentlength/><d:getcontenttype/><ocrclone:integrity-id/></d:prop>
            <d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>
            ${children.joinToString("")}</d:multistatus>
            """.trimIndent().trimStart(),
        )

    // Each argument is one independent DAV response field used by protocol-focused fixtures.
    @Suppress("LongParameterList")
    private fun davListing(
        requestedPath: String,
        requestedId: String,
        requestedName: String,
        requestedFolder: Boolean,
        children: List<String> = emptyList(),
        requestedMarker: String = "",
    ): MockResponse =
        MockResponse().setResponseCode(207).setBody(
            """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">${davEntry(
                requestedPath,
                requestedId,
                requestedName,
                requestedFolder,
                0,
                requestedMarker,
            )}${children.joinToString("")}</d:multistatus>""",
        )

    // These parameters mirror the remote resource fields so tests can state fixtures clearly.
    @Suppress("LongParameterList")
    private fun entry(
        path: String,
        id: String,
        name: String,
        folder: Boolean,
        size: Long = 0,
        marker: String = "",
    ): String = davEntry(path, id, name, folder, size, marker)

    // This low-level XML helper mirrors the DAV entry fields under test.
    @Suppress("LongParameterList")
    private fun davEntry(
        path: String,
        id: String,
        name: String,
        folder: Boolean,
        size: Long,
        marker: String = "",
    ): String {
        val href = if (folder) "${path.trimEnd('/')}/" else path
        val collection = if (folder) "<d:collection/>" else ""
        return """
            <d:response><d:href>$href</d:href><d:propstat><d:prop>
            <d:resourcetype>$collection</d:resourcetype><d:getcontentlength>$size</d:getcontentlength>
            <d:getetag>"tag-$id"</d:getetag><oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>
            $marker
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
            """.trimIndent()
    }

    private class FakeCipher(
        private val onDecrypt: (() -> Unit)? = null,
        private val onExport: (() -> Unit)? = null,
    ) : VaultCipherEngine {
        val closed = AtomicBoolean(false)
        var lastOutput: OutputStream? = null
        var exported: ByteArray? = null

        override fun createIntegrityToken(): String = "test-token"

        override fun verifyIntegrityToken(base64Token: String): Boolean = false

        override fun decryptName(encrypted: String): String = if (encrypted == "cipher") "secret.txt" else encrypted

        override fun decryptPath(encrypted: String): String = encrypted

        override fun encryptName(plain: String): String = plain

        override fun encryptPath(plain: String): String = plain

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            val bytes = input.readBytes()
            require(bytes.size.toLong() <= maximumPlaintextBytes)
            output.write(bytes)
            bytes.fill(0)
            return 0
        }

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            lastOutput = output
            output.write("preview".toByteArray())
            onDecrypt?.invoke()
            return 7
        }

        override fun exportKeyMaterial(): ByteArray =
            ByteArray(80) { it.toByte() }.also {
                exported = it
                onExport?.invoke()
            }

        override fun close() {
            closed.set(true)
        }
    }
}
