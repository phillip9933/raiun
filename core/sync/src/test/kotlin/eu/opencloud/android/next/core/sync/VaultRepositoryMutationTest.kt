package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferConflictException
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString.Companion.encodeUtf8
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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Suppress("LargeClass") // These mutation cases intentionally share one session and MockWebServer fixture.
class VaultRepositoryMutationTest {
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
    fun folderVaultCreationWritesAndReadsBackTheWebProof() =
        runBlocking {
            val cipher = FixtureCipher()
            server.enqueue(graphPersonal())
            server.enqueue(davCollection("/dav/files/", "root", "files"))
            server.enqueue(davCollection("/dav/files/", "root", "files"))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(propertyUpdateResponse())
            server.enqueue(davCollection("/dav/files/Secret.vault/", "vault-id", "Secret.vault", "proof-token"))
            val repository = repository(cipher)
            val password = "secret".toCharArray()

            val location = repository.createFolderVault(account.id, "drive", "", "Secret", password)

            assertTrue(password.all { it == '\u0000' })
            assertEquals(VaultLocationKind.FOLDER_VAULT, location.kind)
            assertEquals("Secret.vault", location.vaultPath)
            assertEquals("vault-id", location.remoteVaultId)
            assertEquals("GET", server.takeRequest().method)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("MKCOL", server.takeRequest().method)
            val proppatch = server.takeRequest()
            assertEquals("PROPPATCH", proppatch.method)
            assertTrue(proppatch.body.readUtf8().contains("<ocrclone:integrity-id>proof-token"))
            assertEquals("PROPFIND", server.takeRequest().method)
            assertTrue(cipher.closed.get())
        }

    @Test
    fun graphVaultSpaceCreationUsesVaultMarkerAndVerifiesProof() =
        runBlocking {
            val cipher = FixtureCipher()
            server.enqueue(MockResponse().setResponseCode(201).setBody("""{"id":"vault-drive"}"""))
            server.enqueue(graphVault())
            val graphRoot = "storage\$space"
            val davRoot = "$graphRoot!space"
            val rootPath = "/dav/spaces/$graphRoot/"
            server.enqueue(davCollection(rootPath, davRoot, "Archive"))
            server.enqueue(propertyUpdateResponse())
            server.enqueue(davCollection(rootPath, davRoot, "Archive", "proof-token"))
            val repository = repository(cipher)
            val password = "secret".toCharArray()

            val location = repository.createVaultSpace(account.id, "Archive", password)

            assertTrue(password.all { it == '\u0000' })
            assertEquals(VaultLocationKind.SPACE_VAULT, location.kind)
            assertEquals("vault-drive", location.driveId)
            assertEquals(davRoot, location.remoteVaultId)
            val create = server.takeRequest()
            assertEquals("POST", create.method)
            assertTrue(create.path.orEmpty().contains("template=none"))
            assertTrue(create.body.readUtf8().contains("application/vnd.opencloud.vault"))
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("PROPPATCH", server.takeRequest().method)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertTrue(cipher.closed.get())
        }

    @Test
    fun uploadEncryptsBeforeConditionalPutAndListsFreshEntry() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val encryptedName = cipher.encryptName("note.txt")
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            // Upload rechecks the authenticated integrity token again immediately before PUT.
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(201).setHeader("ETag", "\"new\""))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$encryptedName", "file-id", encryptedName, 57)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            try {
                val added = session.upload("", "note.txt", ByteArrayInputStream("plaintext".toByteArray()), 9)
                assertEquals("note.txt", added.name)
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("PROPFIND", server.takeRequest().method)
                val put = server.takeRequest()
                assertEquals("PUT", put.method)
                assertEquals("*", put.getHeader("If-None-Match"))
                assertTrue(put.path.orEmpty().endsWith(encryptedName))
                assertTrue(!put.body.readUtf8().contains("plaintext"))
            } finally {
                session.close()
            }
        }

    @Test
    fun overwriteUsesIssuedStrongEtagAndConsumesEntryAfterPreconditionFailure() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val encryptedName = cipher.encryptName("note.txt")
            val plaintext = "replacement plaintext".toByteArray()
            val expectedCiphertext = cipher.encryptBytes(plaintext)
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$encryptedName", "file-id", encryptedName, 49)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(412))
            try {
                val issuedEntry = session.list().single()
                assertEquals("note.txt", issuedEntry.name)
                assertThrows(TransferConflictException::class.java) {
                    runBlocking {
                        session.upload(
                            "",
                            "note.txt",
                            ByteArrayInputStream(plaintext),
                            plaintext.size.toLong(),
                            mimeType = "text/plain",
                            overwrite = issuedEntry,
                        )
                    }
                }

                val requests =
                    (1..5).map {
                        requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)) { "Expected bounded DAV request." }
                    }
                assertEquals(
                    listOf("PROPFIND", "PROPFIND", "PROPFIND", "PROPFIND", "PROPFIND"),
                    requests.map { it.method },
                )
                val put =
                    requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)) { "Expected bounded conditional PUT." }
                assertEquals("PUT", put.method)
                assertEquals("\"tag-file-id\"", put.getHeader("If-Match"))
                assertEquals(null, put.getHeader("If-None-Match"))
                assertTrue(put.path.orEmpty().endsWith(encryptedName))
                assertArrayEquals(expectedCiphertext, put.body.readByteArray())
                assertEquals(6, server.requestCount)

                assertThrows(OpenCloudException::class.java) {
                    runBlocking {
                        session.upload(
                            "",
                            "note.txt",
                            ByteArrayInputStream(plaintext),
                            plaintext.size.toLong(),
                            mimeType = "text/plain",
                            overwrite = issuedEntry,
                        )
                    }
                }
                assertEquals(6, server.requestCount)
            } finally {
                plaintext.fill(0)
                expectedCiphertext.fill(0)
                session.close()
            }
        }

    @Test
    fun uploadStreamsMoreThanEightMiBWithoutPlaintextBuffer() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val encryptedName = cipher.encryptName("large.bin")
            val plainSize = 9L * 1024 * 1024 + 17
            val cipherSize = 32L + plainSize + ((plainSize - 1) / 65536 + 1) * 16
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children =
                        listOf(
                            davFile("$rootPath$encryptedName", "large-id", encryptedName, cipherSize.toInt()),
                        ),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            try {
                val added = session.upload("", "large.bin", PatternInputStream(plainSize), plainSize)
                assertEquals("large.bin", added.name)
                server.takeRequest()
                server.takeRequest()
                val put = server.takeRequest()
                assertEquals(cipherSize, put.bodySize)
                assertEquals(cipherSize.toString(), put.getHeader("Content-Length"))
            } finally {
                session.close()
            }
        }

    @Test
    fun unknownLengthUploadDeletesCiphertextSpoolAfterSuccess() =
        runBlocking {
            val cipher = FixtureCipher()
            val spoolDirectory = Files.createTempDirectory("vault-spool-test").toFile()
            val session = session(cipher, spoolDirectory)
            val rootPath = "/dav/files/Secret.vault/"
            val encryptedName = cipher.encryptName("unknown.bin")
            val plainSize = 9L * 1024 * 1024 + 17
            val cipherSize = 32L + plainSize + ((plainSize - 1) / 65536 + 1) * 16
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children =
                        listOf(
                            davFile("$rootPath$encryptedName", "unknown-id", encryptedName, cipherSize.toInt()),
                        ),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            try {
                val added = session.upload("", "unknown.bin", PatternInputStream(plainSize), -1L)
                assertEquals("unknown.bin", added.name)
                assertTrue(spoolDirectory.listFiles().isNullOrEmpty())
                server.takeRequest()
                server.takeRequest()
                assertEquals(cipherSize, server.takeRequest().bodySize)
            } finally {
                session.close()
                spoolDirectory.deleteRecursively()
            }
        }

    @Test
    fun cancelledUnknownLengthUploadRemovesPartialSpoolBeforePut() =
        runBlocking {
            val spoolDirectory = Files.createTempDirectory("vault-spool-cancel").toFile()
            val session = session(FixtureCipher(), spoolDirectory)
            server.enqueue(davCollection("/dav/files/Secret.vault/", "vault-id", "Secret.vault", "proof-token"))
            val source =
                object : PatternInputStream(512L * 1024) {
                    var reads = 0

                    override fun read(
                        buffer: ByteArray,
                        offset: Int,
                        count: Int,
                    ): Int {
                        if (++reads > 2) throw CancellationException("synthetic cancellation")
                        return super.read(buffer, offset, count)
                    }
                }
            try {
                assertThrows(CancellationException::class.java) {
                    runBlocking { session.upload("", "cancel.bin", source, -1L) }
                }
                assertEquals(1, server.requestCount)
                assertTrue(spoolDirectory.listFiles().isNullOrEmpty())
            } finally {
                session.close()
                spoolDirectory.deleteRecursively()
            }
        }

    @Test
    fun replacedRootAndForgedEntryFailBeforeMutation() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            server.enqueue(davCollection("/dav/files/Secret.vault/", "replacement-id", "Secret.vault"))
            try {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { session.upload("", "note", ByteArrayInputStream(byteArrayOf()), 0) }
                }
                assertEquals(1, server.requestCount)
            } finally {
                session.close()
            }
        }

    @Test
    fun changedIntegrityTokenAtSameRootIdPreventsChildWrite() =
        runBlocking {
            val session = session(FixtureCipher())
            server.enqueue(davCollection("/dav/files/Secret.vault/", "vault-id", "Secret.vault", "changed-token"))
            try {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf()), 0) }
                }
                assertEquals(1, server.requestCount)
                assertEquals("PROPFIND", server.takeRequest().method)
            } finally {
                session.close()
            }
        }

    @Test
    fun renameUsesSameVaultMoveWithSourcePrecondition() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val oldName = cipher.encryptName("note.txt")
            val newName = cipher.encryptName("renamed.txt")
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$oldName", "file-id", oldName, 49)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$newName", "file-id", newName, 49)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            try {
                val entry = session.list().single()
                val renamed = session.rename(entry, "renamed.txt")
                assertEquals("renamed.txt", renamed.name)
                val requests = (1..9).map { server.takeRequest() }
                val move = requests[4]
                assertEquals("MOVE", move.method)
                assertEquals("\"tag-file-id\"", move.getHeader("If-Match"))
                assertEquals("F", move.getHeader("Overwrite"))
                assertTrue(move.getHeader("Destination").orEmpty().endsWith(newName))
            } finally {
                session.close()
            }
        }

    @Test
    fun deleteRejectsEntryWithoutStrongEtagBeforeDeleteRequest() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val rawName = cipher.encryptName("note.txt")
            val weakEntry =
                davFile("$rootPath$rawName", "file-id", rawName, 49)
                    .replace("<d:getetag>\"tag-file-id\"</d:getetag>", "<d:getetag>W/\"weak\"</d:getetag>")
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", children = listOf(weakEntry)))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            try {
                val entry = session.list().single()
                assertThrows(OpenCloudException::class.java) { runBlocking { session.delete(entry) } }
                assertEquals(4, server.requestCount)
                repeat(4) { assertEquals("PROPFIND", server.takeRequest().method) }
            } finally {
                session.close()
            }
        }

    @Test
    fun ambiguousDeleteInvalidatesIssuedEntryUntilRefresh() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val rawName = cipher.encryptName("note.txt")
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$rawName", "file-id", rawName, 49)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
            server.enqueue(MockResponse().setResponseCode(500))
            try {
                val entry = session.list().single()
                assertThrows(TransferHttpException::class.java) { runBlocking { session.delete(entry) } }
                val requestCount = server.requestCount
                assertThrows(OpenCloudException::class.java) { runBlocking { session.delete(entry) } }
                assertEquals(requestCount, server.requestCount)
            } finally {
                session.close()
            }
        }

    @Test
    fun downloadAuthenticatesCiphertextBeforeWritingPlaintextToSink() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val rawName = cipher.encryptName("note.txt")
            val plaintext = "private text".toByteArray()
            val ciphertext = cipher.encryptBytes(plaintext)
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("$rootPath$rawName", "file-id", rawName, ciphertext.size)),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(MockResponse().setBody(okio.Buffer().write(ciphertext)))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            val sink = ByteArrayOutputStream()
            try {
                val entry = session.list().single()
                repeat(3) { assertEquals("PROPFIND", server.takeRequest().method) }
                val bytesWritten = session.download(entry, sink)
                assertEquals(plaintext.size.toLong(), bytesWritten)
                assertArrayEquals(plaintext, sink.toByteArray())
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("GET", server.takeRequest().method)
                assertEquals("PROPFIND", server.takeRequest().method)
            } finally {
                ciphertext.fill(0)
                plaintext.fill(0)
                session.close()
            }
        }

    @Test
    fun downloadStreamsMoreThanEightMiBIntoCallerSink() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val rawName = cipher.encryptName("large.bin")
            val plainSize = 8L * 1024 * 1024 + 17
            val encrypted = ByteArrayOutputStream()
            cipher.encryptContent(PatternInputStream(plainSize), encrypted, plainSize)
            val ciphertext = encrypted.toByteArray()
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children =
                        listOf(
                            davFile("$rootPath$rawName", "large-id", rawName, ciphertext.size),
                        ),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(MockResponse().setBody(okio.Buffer().write(ciphertext)))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            val sink = PatternCheckingOutputStream()
            try {
                val entry = session.list().single()
                assertEquals(plainSize, session.download(entry, sink))
                assertEquals(plainSize, sink.bytesWritten)
            } finally {
                ciphertext.fill(0)
                session.close()
            }
        }

    @Test
    fun damagedFinalBlockFailsWithoutWritingThatBlock() =
        runBlocking {
            val cipher = FixtureCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val rawName = cipher.encryptName("damaged.bin")
            val plainSize = 65536L + 17
            val encrypted = ByteArrayOutputStream()
            cipher.encryptContent(PatternInputStream(plainSize), encrypted, plainSize)
            val ciphertext = encrypted.toByteArray().also { it[it.lastIndex] = 0 }
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    rootPath,
                    "vault-id",
                    "Secret.vault",
                    children =
                        listOf(
                            davFile("$rootPath$rawName", "damaged-id", rawName, ciphertext.size),
                        ),
                ),
            )
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
            server.enqueue(MockResponse().setBody(okio.Buffer().write(ciphertext)))
            val sink = PatternCheckingOutputStream()
            try {
                val entry = session.list().single()
                assertThrows(IllegalArgumentException::class.java) {
                    runBlocking { session.download(entry, sink) }
                }
                assertEquals(65536L, sink.bytesWritten)
            } finally {
                ciphertext.fill(0)
                session.close()
            }
        }

    @Test
    fun sessionCloseRevokesIssuedEntriesBeforeNetworkMutation() =
        runBlocking {
            val session = session(FixtureCipher())
            val encryptedName = FixtureCipher().encryptName("note.txt")
            server.enqueue(davCollection("/dav/files/Secret.vault/", "vault-id", "Secret.vault"))
            server.enqueue(
                davCollection(
                    "/dav/files/Secret.vault/",
                    "vault-id",
                    "Secret.vault",
                    children = listOf(davFile("/dav/files/Secret.vault/$encryptedName", "file-id", encryptedName, 55)),
                ),
            )
            server.enqueue(davCollection("/dav/files/Secret.vault/", "vault-id", "Secret.vault"))
            val entry = session.list().single()
            val requestCount = server.requestCount
            session.close()
            assertThrows(OpenCloudException::class.java) { runBlocking { session.delete(entry) } }
            assertEquals(requestCount, server.requestCount)
        }

    @Test
    fun accountSnapshotChangeRevokesSessionBeforeNetworkRead() =
        runBlocking {
            val session = session(FixtureCipher())
            database.accountDao().upsert(account.copy(displayName = "Changed"))

            assertThrows(OpenCloudException::class.java) {
                runBlocking { session.encodeDirectoryPath("folder") }
            }
            assertEquals(0, server.requestCount)
            session.close()
        }

    private fun repository(cipher: FixtureCipher) =
        VaultRepository(
            store,
            { "Bearer test" },
            { OkHttpClient() },
            EndpointPolicy(true),
            { { true } },
            VaultCipherFactories({ cipher }, { cipher }),
        )

    private fun session(
        cipher: FixtureCipher,
        spoolDirectory: java.io.File? = null,
    ): VaultSession {
        val location =
            VaultLocation(
                account.id,
                "Secret.vault",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault-id",
                "root-id",
                account.serverUrl,
                server.url("dav/files/").toString(),
                "Secret.vault",
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
            location,
            cipher,
            VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
            access,
            { true },
            spoolDirectory,
        )
    }

    private fun graphPersonal(): MockResponse {
        val webDav = server.url("dav/files/")
        return MockResponse().setBody(
            """{"value":[{"id":"drive","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"$webDav"}}]}""",
        )
    }

    private fun graphVault(): MockResponse {
        val graphRoot = "storage\$space"
        val webDav = server.url("dav/spaces/$graphRoot/")
        return MockResponse().setBody(
            """{"value":[{"id":"vault-drive","name":"Archive","driveType":"project","@libre.graph.contentType":"application/vnd.opencloud.vault","root":{"id":"$graphRoot","webDavUrl":"$webDav"}}]}""",
        )
    }

    private fun propertyUpdateResponse(): MockResponse =
        MockResponse().setResponseCode(207).setBody(
            """<d:multistatus xmlns:d="DAV:" xmlns:ocrclone="ocrclone"><d:response><d:propstat><d:prop><ocrclone:integrity-id/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
        )

    private fun davCollection(
        path: String,
        id: String,
        name: String,
        token: String? = null,
        children: List<String> = emptyList(),
    ): MockResponse {
        val trailingPath = if (path.endsWith('/')) path else "$path/"
        val tokenProperty = token?.let { "<ocrclone:integrity-id>$it</ocrclone:integrity-id>" }.orEmpty()
        return MockResponse().setResponseCode(207).setBody(
            """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:response><d:href>$trailingPath</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"tag-$id"</d:getetag><oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$tokenProperty</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>${children.joinToString(
                "",
            )}</d:multistatus>""",
        )
    }

    private fun davFile(
        path: String,
        id: String,
        name: String,
        size: Int,
    ): String =
        """<d:response><d:href>$path</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>$size</d:getcontentlength><d:getetag>"tag-$id"</d:getetag><oc:fileid>$id</oc:fileid><oc:name>$name</oc:name></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""

    private class FixtureCipher : VaultCipherEngine {
        val closed = AtomicBoolean(false)

        override fun createIntegrityToken() = "proof-token"

        override fun verifyIntegrityToken(base64Token: String) = base64Token == "proof-token"

        override fun encryptName(plain: String) =
            "enc_" + Base64.getUrlEncoder().withoutPadding().encodeToString(plain.encodeUtf8().toByteArray())

        override fun decryptName(encrypted: String): String =
            String(Base64.getUrlDecoder().decode(encrypted.removePrefix("enc_")))

        override fun encryptPath(plain: String) =
            if (plain.isEmpty()) {
                ""
            } else {
                plain.split('/').joinToString("/") {
                    encryptName(it)
                }
            }

        override fun decryptPath(encrypted: String) =
            if (encrypted.isEmpty()) {
                ""
            } else {
                encrypted.split('/').joinToString("/") {
                    decryptName(it)
                }
            }

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            output.write(ByteArray(32) { 7 })
            val block = ByteArray(65536)
            var total = 0L
            try {
                while (true) {
                    val count = readBlock(input, block)
                    if (count == 0) return total
                    require(count.toLong() <= maximumPlaintextBytes - total)
                    for (index in 0 until count) block[index] = (block[index].toInt() xor 0x5a).toByte()
                    output.write(block, 0, count)
                    output.write(ByteArray(16) { 9 })
                    total += count
                    if (count < block.size) return total
                }
            } finally {
                block.fill(0)
            }
        }

        fun encryptBytes(plaintext: ByteArray): ByteArray =
            ByteArrayOutputStream()
                .also {
                    encryptContent(ByteArrayInputStream(plaintext), it, plaintext.size.toLong())
                }.toByteArray()

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            val header = ByteArray(32)
            require(readBlock(input, header) == header.size && header.all { it == 7.toByte() })
            val block = ByteArray(65552)
            var total = 0L
            try {
                while (true) {
                    val count = readBlock(input, block)
                    if (count == 0) return total
                    require(count >= 16 && block.sliceArray(count - 16 until count).all { it == 9.toByte() })
                    val plainSize = count - 16
                    require(plainSize.toLong() <= maximumPlaintextBytes - total)
                    for (index in 0 until plainSize) block[index] = (block[index].toInt() xor 0x5a).toByte()
                    output.write(block, 0, plainSize)
                    total += plainSize
                    if (count < block.size) return total
                }
            } finally {
                header.fill(0)
                block.fill(0)
            }
        }

        private fun readBlock(
            input: InputStream,
            block: ByteArray,
        ): Int {
            var count = 0
            while (count < block.size) {
                val read = input.read(block, count, block.size - count)
                if (read < 0) break
                if (read > 0) count += read
            }
            return count
        }

        override fun exportKeyMaterial() = ByteArray(80)

        override fun close() {
            closed.set(true)
        }
    }

    private open class PatternInputStream(
        private val length: Long,
    ) : InputStream() {
        private var position = 0L

        override fun read(): Int = if (position < length) ((position++ % 251).toInt()) else -1

        override fun read(
            buffer: ByteArray,
            offset: Int,
            count: Int,
        ): Int {
            if (position >= length) return -1
            val size = minOf(count.toLong(), length - position).toInt()
            repeat(size) { index -> buffer[offset + index] = ((position + index) % 251).toByte() }
            position += size
            return size
        }
    }

    private class PatternCheckingOutputStream : OutputStream() {
        var bytesWritten = 0L
            private set

        override fun write(value: Int) {
            assertEquals((bytesWritten % 251).toInt(), value and 0xff)
            bytesWritten++
        }

        override fun write(
            buffer: ByteArray,
            offset: Int,
            count: Int,
        ) {
            repeat(count) { index -> write(buffer[offset + index].toInt()) }
        }
    }
}
