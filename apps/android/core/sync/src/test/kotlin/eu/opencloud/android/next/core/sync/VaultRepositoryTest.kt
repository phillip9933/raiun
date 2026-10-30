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

    @Test
    fun `chunked large vault directory pages without publishing its complete plaintext listing`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            val children =
                (0 until 6000).map { number ->
                    entry("$root/opaque-$number", "id-$number", "opaque-$number", number % 3 == 0, 48)
                }
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            val rootEntry = davEntry(root, "vault-id", "Secret.vault", true, 0)
            val xml =
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">" +
                    rootEntry + children.joinToString("") + "</d:multistatus>"
            server.enqueue(MockResponse().setResponseCode(207).setChunkedBody(xml, 113))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), FakeCipher())
            try {
                session.openDirectory().use { snapshot ->
                    assertEquals(6000L, snapshot.totalCount)
                    assertEquals(0, session.issuedEntryCountForTesting())
                    val first = snapshot.page(0, 17)
                    assertEquals(17, first.size)
                    assertTrue(first.all { it.isFolder })
                    assertEquals(17, session.issuedEntryCountForTesting())
                    val next = snapshot.page(17, 17)
                    assertTrue(first.map(VaultFolder::id).intersect(next.map(VaultFolder::id).toSet()).isEmpty())
                    assertEquals(17, session.issuedEntryCountForTesting())
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { session.download(first.first(), ByteArrayOutputStream()) }
                    }
                    assertEquals(3, server.requestCount)
                    assertEquals(listOf("0", "1", "0"), List(3) { server.takeRequest().getHeader("Depth") })
                }
                assertEquals(0, session.issuedEntryCountForTesting())
            } finally {
                session.close()
            }
        }

    @Test
    fun `late duplicate identity never publishes a partial decrypted directory`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            val children =
                (0 until 257).map { number ->
                    entry("$root/opaque-$number", "id-$number", "opaque-$number", false, 48)
                } +
                    entry("$root/last", "id-0", "last", false, 48)
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
            val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), FakeCipher())
            try {
                assertThrows(OpenCloudException::class.java) { runBlocking { session.openDirectory() } }
                assertEquals(0, session.issuedEntryCountForTesting())
            } finally {
                session.close()
            }
        }

    @Test
    fun `root replacement after streamed decryption prevents snapshot publication`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    root,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(entry("$root/cipher", "child", "cipher", false, 48)),
                ),
            )
            server.enqueue(davListing(root, "replacement-id", "Secret.vault", true))
            val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), FakeCipher())
            try {
                assertThrows(OpenCloudException::class.java) { runBlocking { session.openDirectory() } }
                assertEquals(0, session.issuedEntryCountForTesting())
            } finally {
                session.close()
            }
        }

    @Test
    fun `refresh and generation revocation invalidate existing directory snapshots`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            repeat(6) { server.enqueue(davListing(root, "vault-id", "Secret.vault", true)) }
            val current = AtomicBoolean(true)
            val session =
                session(
                    VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                    FakeCipher(),
                    generationIsCurrent = current::get,
                )
            try {
                val old = session.openDirectory()
                val fresh = session.openDirectory()
                assertThrows(OpenCloudException::class.java) { runBlocking { old.page() } }
                current.set(false)
                assertThrows(OpenCloudException::class.java) { runBlocking { fresh.page() } }
                assertEquals(0, session.issuedEntryCountForTesting())
            } finally {
                session.close()
            }
        }

    @Test
    fun `decryption failure after completed sort runs removes the private directory stage`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    root,
                    "vault-id",
                    "Secret.vault",
                    true,
                    (0 until 300).map { entry("$root/name-$it", "id-$it", "name-$it", false, 48) },
                ),
            )
            var decrypted = 0
            val engine =
                FakeCipher(onName = {
                    if (++decrypted ==
                        258
                    ) {
                        throw OpenCloudException(eu.opencloud.android.next.core.network.OpenCloudError.InvalidResponse)
                    }
                })
            val stage =
                java.nio.file.Files
                    .createTempDirectory("vault-failed-directory")
                    .toFile()
            val session =
                session(
                    VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                    engine,
                    spoolDirectory = stage,
                )
            try {
                assertThrows(OpenCloudException::class.java) { runBlocking { session.openDirectory() } }
                assertEquals(258, decrypted)
                assertEquals(0, session.issuedEntryCountForTesting())
                assertTrue(stage.walkTopDown().none { it.isFile })
            } finally {
                session.close()
                stage.deleteRecursively()
            }
        }

    @Test
    fun `cancellation during streamed name decryption removes all staged ciphertext runs`() {
        val root = "/dav/files/parent/Secret.vault"
        server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
        server.enqueue(
            davListing(
                root,
                "vault-id",
                "Secret.vault",
                true,
                (0 until 300).map { entry("$root/name-$it", "id-$it", "name-$it", false, 48) },
            ),
        )
        val job = SupervisorJob()
        var decrypted = 0
        val engine = FakeCipher(onName = { if (++decrypted == 258) job.cancel() })
        val stage =
            java.nio.file.Files
                .createTempDirectory("vault-cancelled-directory")
                .toFile()
        val session =
            session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), engine, spoolDirectory = stage)
        val scope = kotlinx.coroutines.CoroutineScope(job + Dispatchers.Unconfined)
        try {
            val pending = scope.async { session.openDirectory() }
            assertThrows(CancellationException::class.java) { runBlocking { pending.await() } }
            assertEquals(0, session.issuedEntryCountForTesting())
            assertTrue(stage.walkTopDown().none { it.isFile })
        } finally {
            scope.cancel()
            session.close()
            stage.deleteRecursively()
        }
    }

    @Test
    fun `hidden visibility is applied before snapshot count and page boundaries after validating every name`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            val children =
                (0 until 301).map { number ->
                    val name = if (number % 2 == 0) ".hidden-$number" else "visible-$number"
                    entry("$root/$name", "id-$number", name, false, 48)
                }
            repeat(2) {
                server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
                server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
                server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            }
            var decrypted = 0
            val session =
                session(
                    VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                    FakeCipher(onName = { decrypted++ }),
                )
            try {
                session.openDirectory().use { visible ->
                    assertEquals(150L, visible.totalCount)
                    val first = visible.page(0, 128)
                    val second = visible.page(first.size.toLong(), 128)
                    assertEquals(128, first.size)
                    assertEquals(22, second.size)
                    assertTrue((first + second).none { it.name.startsWith('.') })
                }
                assertEquals(301, decrypted)
                session.openDirectory(showHidden = true).use { all ->
                    assertEquals(301L, all.totalCount)
                    assertTrue(all.page().any { it.name.startsWith('.') })
                }
                assertEquals(602, decrypted)
            } finally {
                session.close()
            }
        }

    @Test
    fun `a decryption failure in a hidden child still prevents publication`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    root,
                    "vault-id",
                    "Secret.vault",
                    true,
                    listOf(
                        entry("$root/visible", "visible-id", "visible", false, 48),
                        entry("$root/.hidden", "hidden-id", ".hidden", false, 48),
                    ),
                ),
            )
            val session =
                session(
                    VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                    FakeCipher(onName = {
                        if (it ==
                            ".hidden"
                        ) {
                            throw OpenCloudException(
                                eu.opencloud.android.next.core.network.OpenCloudError.InvalidResponse,
                            )
                        }
                    }),
                )
            try {
                assertThrows(OpenCloudException::class.java) { runBlocking { session.openDirectory() } }
                assertEquals(0, session.issuedEntryCountForTesting())
            } finally {
                session.close()
            }
        }

    @Test
    fun `large unlock validates the entire stream before trying the first proof file`() =
        runTest {
            val path = "parent/Secret.vault"
            val root = "/dav/files/$path"
            val children = (0 until 6000).map { entry("$root/proof-$it", "file-$it", "proof-$it", false, 49) }
            server.enqueue(graphPage())
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
            server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(49))))
            repository().unlock(account.id, personalLocation(), path, charArrayOf('p')).use { session ->
                assertEquals("vault-id", session.identity.remoteVaultId)
            }
            assertEquals(3, server.requestCount)
            server.takeRequest()
            assertEquals("1", server.takeRequest().getHeader("Depth"))
            assertEquals("$root/proof-0", server.takeRequest().path)
        }

    @Test
    fun `large unlock preserves eight file proof attempts and rejects a wrong password`() =
        runTest {
            val path = "parent/Secret.vault"
            val root = "/dav/files/$path"
            val children =
                listOf(entry("$root/empty", "empty-id", "empty", false, 32)) +
                    (0 until 6000).map { entry("$root/proof-$it", "file-$it", "proof-$it", false, 49) }
            server.enqueue(graphPage())
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
            repeat(8) { server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(49)))) }
            var proofs = 0
            val engine =
                FakeCipher(onDecrypt = {
                    proofs++
                    throw SecurityException("synthetic wrong key")
                })
            val failure =
                assertThrows(VaultUnlockException::class.java) {
                    runBlocking {
                        repository(
                            cipher = engine,
                        ).unlock(account.id, personalLocation(), path, charArrayOf('x'))
                    }
                }
            assertEquals(VaultUnlockFailure.PASSWORD_NOT_PROVEN, failure.failure)
            assertEquals(8, proofs)
            assertEquals(10, server.requestCount)
            server.takeRequest()
            server.takeRequest()
            repeat(8) { assertEquals("$root/proof-$it", server.takeRequest().path) }
            assertTrue(engine.closed.get())
        }

    @Test
    fun `late duplicate after enough proof candidates rejects unlock before any ciphertext request`() =
        runTest {
            val path = "parent/Secret.vault"
            val root = "/dav/files/$path"
            val children =
                (0 until 6000).map { entry("$root/proof-$it", "file-$it", "proof-$it", false, 49) } +
                    entry("$root/duplicate", "file-0", "duplicate", false, 49)
            server.enqueue(graphPage())
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository().unlock(account.id, personalLocation(), path, charArrayOf('p')) }
            }
            assertEquals(2, server.requestCount)
        }

    @Test
    fun `destination exclusion counts exact and descendant paths while preserving similar prefixes`() =
        runTest {
            val root = "/dav/files/parent/Secret.vault"
            val names = listOf("source", "source-extra") + (0 until 130).map { "other-$it" }
            val children = names.mapIndexed { number, name -> entry("$root/$name", "id-$number", name, true) }
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, children))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(
                davListing(
                    "$root/source",
                    "source-id",
                    "source",
                    true,
                    listOf(entry("$root/source/child", "nested-id", "child", true)),
                ),
            )
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            val session = session(VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)), FakeCipher())
            try {
                session.openDirectory(excludedPath = "source").use { snapshot ->
                    assertEquals(131L, snapshot.totalCount)
                    val first = snapshot.page(0, 128)
                    val second = snapshot.page(first.size.toLong(), 128)
                    assertEquals(3, second.size)
                    assertTrue((first + second).any { it.path == "source-extra" })
                    assertTrue((first + second).none { it.path == "source" })
                }
                session.openDirectory("source", excludedPath = "source").use { snapshot ->
                    assertEquals(0L, snapshot.totalCount)
                }
                listOf("", "../source", "/source").forEach { excluded ->
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { session.openDirectory(excludedPath = excluded) }
                    }
                }
            } finally {
                session.close()
            }
        }

    @Test
    fun `current page offline status preserves issued identity without decrypting an offline listing`() =
        runTest {
            val path = "parent/Secret.vault"
            val root = "/dav/files/$path"
            val child = entry("$root/cipher", "file-id", "cipher", false, 49)
            server.enqueue(graphPage())
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, listOf(child)))
            server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(49))))
            val session = repository().unlock(account.id, personalLocation(), path, charArrayOf('p'))
            val directory =
                java.nio.file.Files
                    .createTempDirectory("vault-bounded-status")
                    .toFile()
            val material = session.exportVerifiedKeyMaterial()
            var nameDecryptions = 0
            val offline =
                VaultOfflineStore(directory, { store.account(it) }, { { true } }, EndpointPolicy(true), {
                    FakeCipher(onName = {
                        nameDecryptions++
                        error("Offline status must not decrypt names")
                    })
                }, durability = jvmOfflineDurability(directory))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true, listOf(child)))
            server.enqueue(davListing(root, "vault-id", "Secret.vault", true))
            try {
                session.openDirectory().use { snapshot ->
                    val page = snapshot.page()
                    offline.pinFile(
                        session.identity,
                        session.location,
                        page.single(),
                        material,
                    ) { it.write(ByteArray(49)) }
                    assertEquals(page, session.offlineFiles(offline, page))
                    assertEquals(0, nameDecryptions)
                    val newerPage = snapshot.page()
                    assertThrows(OpenCloudException::class.java) { runBlocking { session.offlineFiles(offline, page) } }
                    assertEquals(newerPage, session.offlineFiles(offline, newerPage))
                    assertEquals(0, nameDecryptions)
                }
            } finally {
                session.close()
                material.fill(0)
                directory.deleteRecursively()
            }
        }

    @Test
    fun `a selected vault root identity cannot change during streamed unlock admission`() =
        runTest {
            val path = "parent/Secret.vault"
            val root = "/dav/files/$path"
            val selected =
                personalLocation().copy(
                    kind = VaultLocationKind.FOLDER_VAULT,
                    isVaultRoot = true,
                    remoteVaultId = "vault-id",
                    vaultPath = path,
                )
            server.enqueue(graphPage())
            server.enqueue(
                davListing(
                    root,
                    "different-id",
                    "Secret.vault",
                    true,
                    (0 until 6000).map { entry("$root/proof-$it", "file-$it", "proof-$it", false, 49) },
                ),
            )
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository().unlock(account.id, selected, password = charArrayOf('p')) }
                }
            assertEquals(eu.opencloud.android.next.core.network.OpenCloudError.PreconditionFailed, failure.error)
            assertEquals(2, server.requestCount)
            server.takeRequest()
            assertEquals("0", server.takeRequest().getHeader("Depth"))
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
        spoolDirectory: java.io.File? = null,
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
            spoolDirectory,
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
        private val onName: ((String) -> Unit)? = null,
    ) : VaultCipherEngine {
        val closed = AtomicBoolean(false)
        var lastOutput: OutputStream? = null
        var exported: ByteArray? = null

        override fun createIntegrityToken(): String = "test-token"

        override fun verifyIntegrityToken(base64Token: String): Boolean = false

        override fun decryptName(encrypted: String): String {
            onName?.invoke(encrypted)
            return if (encrypted == "cipher") "secret.txt" else encrypted
        }

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
