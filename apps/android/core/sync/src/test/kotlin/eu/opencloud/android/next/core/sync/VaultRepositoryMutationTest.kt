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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
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
import java.util.concurrent.TimeUnit

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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
                assertSpoolFilesRemoved(spoolDirectory)
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
            val session = session(VaultBoundaryTestCipher(), spoolDirectory)
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
                assertSpoolFilesRemoved(spoolDirectory)
            } finally {
                session.close()
                spoolDirectory.deleteRecursively()
            }
        }

    @Test
    fun replacedRootAndForgedEntryFailBeforeMutation() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
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
            val session = session(VaultBoundaryTestCipher())
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val cipher = VaultBoundaryTestCipher()
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
            val session = session(VaultBoundaryTestCipher())
            val encryptedName = VaultBoundaryTestCipher().encryptName("note.txt")
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
            val session = session(VaultBoundaryTestCipher())
            database.accountDao().upsert(account.copy(displayName = "Changed"))

            assertThrows(OpenCloudException::class.java) {
                runBlocking { session.encodeDirectoryPath("folder") }
            }
            assertEquals(0, server.requestCount)
            session.close()
        }

    @Test fun backgroundReplacementStagesExactIssuedVersionAndConsumesOnlyAfterAdmission() =
        runBlocking<Unit> {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val root = Files.createTempDirectory("vault-replacement-staging").toFile()
            val payloads = VaultUploadStore(root)
            val encryptedName = cipher.encryptName("note.txt")
            val rootPath = "/dav/files/Secret.vault/"
            server.dispatcher =
                object : okhttp3.mockwebserver.Dispatcher() {
                    override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse {
                        assertEquals("PROPFIND", request.method)
                        return davCollection(
                            rootPath,
                            "vault-id",
                            "Secret.vault",
                            "proof-token",
                            listOf(davFile("$rootPath$encryptedName", "file-id", encryptedName, 49)),
                        )
                    }
                }
            try {
                val entry = session.list().single()
                val before = server.requestCount
                assertThrows(OpenCloudException::class.java) {
                    runBlocking {
                        session.prepareBackgroundReplacement(
                            payloads,
                            entry.copy(encryptedPath = "Secret.vault/other"),
                            "edited".byteInputStream(),
                            6,
                            { true },
                        )
                    }
                }
                assertEquals(before, server.requestCount)
                assertTrue(payloads.ids().isEmpty())
                val plain = "edited".toByteArray()
                val job =
                    session.prepareBackgroundReplacement(
                        payloads,
                        entry,
                        plain.inputStream(),
                        plain.size.toLong(),
                        { true },
                    )
                assertEquals(entry.encryptedPath, job.destination)
                assertEquals(entry.strongETag, job.expectedETag)
                payloads.open(job).use { assertArrayEquals(cipher.encryptBytes(plain), it.readBytes()) }
                assertEquals(job, payloads.read(job.id))
                session.acknowledgeBackgroundReplacement(entry)
                assertThrows(OpenCloudException::class.java) {
                    runBlocking {
                        session.prepareBackgroundReplacement(
                            payloads,
                            entry,
                            plain.inputStream(),
                            plain.size.toLong(),
                            { true },
                        )
                    }
                }
            } finally {
                session.close()
                root.deleteRecursively()
            }
        }

    @Test fun cancelledBackgroundReplacementDeletesIncompleteCiphertextAndKeepsIssuedVersion() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val root = Files.createTempDirectory("vault-replacement-cancel").toFile()
            val payloads = VaultUploadStore(root)
            val encryptedName = cipher.encryptName("note.txt")
            val rootPath = "/dav/files/Secret.vault/"
            server.dispatcher =
                object : okhttp3.mockwebserver.Dispatcher() {
                    override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                        davCollection(
                            rootPath,
                            "vault-id",
                            "Secret.vault",
                            "proof-token",
                            listOf(davFile("$rootPath$encryptedName", "file-id", encryptedName, 49)),
                        )
                }
            try {
                val entry = session.list().single()
                val cancelled =
                    object : InputStream() {
                        override fun read(): Int = throw CancellationException("Synthetic cancelled preparation")
                    }
                assertThrows(CancellationException::class.java) {
                    runBlocking { session.prepareBackgroundReplacement(payloads, entry, cancelled, 6, { true }) }
                }
                assertTrue(payloads.ids().isEmpty())
                val retry =
                    session.prepareBackgroundReplacement(
                        payloads,
                        entry,
                        "edited".byteInputStream(),
                        6,
                        { true },
                    )
                assertEquals(entry.strongETag, retry.expectedETag)
            } finally {
                session.close()
                root.deleteRecursively()
            }
        }

    @Test
    fun postWriteLargeDirectoryIssuesOnlyTheMatchingDestination() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val name = cipher.encryptName("note.txt")
            val children =
                listOf(davFile("$rootPath$name", "created-id", name, 49)) +
                    (0 until 6000).map { number ->
                        val encrypted = cipher.encryptName("sibling-$number.txt")
                        davFile("$rootPath$encrypted", "sibling-$number", encrypted, 49)
                    }
            enqueueUploadResult(rootPath, children)
            try {
                val created = session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf(1)), 1)
                assertEquals("created-id", created.id)
                assertEquals("note.txt", created.name)
                assertEquals(1, session.issuedEntryCountForTesting())
                assertEquals(7, server.requestCount)
            } finally {
                session.close()
            }
        }

    @Test
    fun lateDuplicateAfterSuccessfulPutNeverIssuesTheEarlierMatchingDestination() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val name = cipher.encryptName("note.txt")
            val duplicate = cipher.encryptName("duplicate.txt")
            val children =
                listOf(davFile("$rootPath$name", "created-id", name, 49)) +
                    (0 until 257).map { number ->
                        val encrypted = cipher.encryptName("sibling-$number.txt")
                        davFile("$rootPath$encrypted", "sibling-$number", encrypted, 49)
                    } + davFile("$rootPath$duplicate", "created-id", duplicate, 49)
            enqueueUploadResult(rootPath, children, finalRoot = false)
            try {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf(1)), 1) }
                }
                assertEquals(0, session.issuedEntryCountForTesting())
                assertEquals(6, server.requestCount)
                val methods = List(6) { requireNotNull(server.takeRequest().method) }
                assertEquals(1, methods.count { it == "PUT" })
            } finally {
                session.close()
            }
        }

    @Test
    fun lateUndecryptableSiblingAfterSuccessfulPutCannotPublishAnEarlierDestination() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val name = cipher.encryptName("note.txt")
            val children =
                listOf(davFile("$rootPath$name", "created-id", name, 49)) +
                    (0 until 257).map { number ->
                        val encrypted = cipher.encryptName("sibling-$number.txt")
                        davFile("$rootPath$encrypted", "sibling-$number", encrypted, 49)
                    } + davFile("${rootPath}invalid!", "invalid-id", "invalid!", 49)
            enqueueUploadResult(rootPath, children, finalRoot = false)
            try {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf(1)), 1) }
                }
                assertEquals(0, session.issuedEntryCountForTesting())
                assertEquals(6, server.requestCount)
            } finally {
                session.close()
            }
        }

    @Test
    fun cancellationAfterPutDuringDestinationValidationIssuesNoEntry() {
        val job = SupervisorJob()
        var names = 0
        val cipher = VaultBoundaryTestCipher(onName = { if (++names == 258) job.cancel() })
        val session = session(cipher)
        val rootPath = "/dav/files/Secret.vault/"
        val name = cipher.encryptName("note.txt")
        val children =
            listOf(davFile("$rootPath$name", "created-id", name, 49)) +
                (0 until 300).map { number ->
                    val encrypted = cipher.encryptName("sibling-$number.txt")
                    davFile("$rootPath$encrypted", "sibling-$number", encrypted, 49)
                }
        enqueueUploadResult(rootPath, children, finalRoot = false)
        val scope = kotlinx.coroutines.CoroutineScope(job + Dispatchers.Unconfined)
        try {
            val result = scope.async { session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf(1)), 1) }
            assertThrows(CancellationException::class.java) { runBlocking { result.await() } }
            assertEquals(0, session.issuedEntryCountForTesting())
            assertEquals(6, server.requestCount)
            assertEquals(1, List(6) { server.takeRequest().method }.count { it == "PUT" })
        } finally {
            scope.cancel()
            session.close()
        }
    }

    @Test
    fun backgroundPreparationAndCaptureStreamLargeRootMetadataWithoutChangingAdmission() =
        runBlocking {
            val cipher = VaultBoundaryTestCipher()
            val session = session(cipher)
            val rootPath = "/dav/files/Secret.vault/"
            val encryptedName = cipher.encryptName("note.txt")
            val target = davFile("$rootPath$encryptedName", "target-id", encryptedName, 49)
            repeat(3) {
                server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token", listOf(target)))
            }
            val staging = Files.createTempDirectory("vault-root-stream-jobs").toFile()
            try {
                val entry = session.list().single()
                val children =
                    listOf(target) +
                        (0 until 6000).map { number ->
                            val name = cipher.encryptName("sibling-$number.txt")
                            davFile("$rootPath$name", "sibling-$number", name, 49)
                        }
                repeat(8) {
                    server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token", children))
                }
                val uploads = VaultUploadStore(File(staging, "uploads"))
                val created =
                    session.prepareBackgroundUpload(
                        uploads,
                        "",
                        "new.txt",
                        byteArrayOf(1).inputStream(),
                        1,
                        { true },
                    )
                assertEquals(null, created.expectedETag)
                val replacement =
                    session.prepareBackgroundReplacement(
                        uploads,
                        entry,
                        byteArrayOf(2).inputStream(),
                        1,
                        { true },
                    )
                assertEquals(entry.strongETag, replacement.expectedETag)
                val captured = session.captureBackgroundDownload(VaultDownloadStore(File(staging, "downloads")), entry)
                assertEquals(entry.id, captured.source.id)
                assertEquals(entry.strongETag, captured.source.strongETag)
                assertEquals(created.rootProofDigest, captured.rootProofDigest)
                assertEquals(1, session.issuedEntryCountForTesting())
                assertEquals(11, server.requestCount)
            } finally {
                session.close()
                staging.deleteRecursively()
            }
        }

    @Test
    fun cancelledPublicMutationDispatcherHandoffRevokesTheSinglePublishedResult() {
        val queue = java.util.concurrent.LinkedBlockingQueue<Runnable>()
        val dispatcher =
            object : kotlinx.coroutines.CoroutineDispatcher() {
                override fun dispatch(
                    context: kotlin.coroutines.CoroutineContext,
                    block: Runnable,
                ) {
                    queue.add(block)
                }
            }
        val job = SupervisorJob()
        val scope = kotlinx.coroutines.CoroutineScope(job + dispatcher)
        val cipher = VaultBoundaryTestCipher()
        val session = session(cipher)
        val rootPath = "/dav/files/Secret.vault/"
        val name = cipher.encryptName("note.txt")
        enqueueUploadResult(rootPath, listOf(davFile("$rootPath$name", "created-id", name, 49)))
        try {
            val result = scope.async { session.upload("", "note.txt", ByteArrayInputStream(byteArrayOf(1)), 1) }
            requireNotNull(queue.poll(5, TimeUnit.SECONDS)).run()
            val handoff = requireNotNull(queue.poll(30, TimeUnit.SECONDS))
            assertEquals(1, session.issuedEntryCountForTesting())
            job.cancel()
            handoff.run()
            assertThrows(CancellationException::class.java) { runBlocking { result.await() } }
            assertEquals(0, session.issuedEntryCountForTesting())
        } finally {
            scope.cancel()
            session.close()
        }
    }

    private fun enqueueUploadResult(
        rootPath: String,
        children: List<String>,
        finalRoot: Boolean = true,
    ) {
        server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
        server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", "proof-token"))
        server.enqueue(MockResponse().setResponseCode(201))
        server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
        server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
        server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault", children = children))
        if (finalRoot) server.enqueue(davCollection(rootPath, "vault-id", "Secret.vault"))
    }

    private fun assertSpoolFilesRemoved(directory: File) {
        assertTrue(directory.isDirectory)
        assertTrue(!Files.isSymbolicLink(directory.toPath()))
        requireNotNull(directory.listFiles()).forEach { child ->
            // Root validation reuses this owned container; no spool, SQLite, or nested file may remain.
            assertEquals("discovery-stage", child.name)
            assertTrue(!Files.isSymbolicLink(child.toPath()))
            assertTrue(child.isDirectory)
            assertTrue(requireNotNull(child.listFiles()).isEmpty())
        }
    }

    private fun repository(cipher: VaultBoundaryTestCipher) =
        VaultRepository(
            store,
            { "Bearer test" },
            { OkHttpClient() },
            EndpointPolicy(true),
            { { true } },
            VaultCipherFactories({ cipher }, { cipher }),
        )

    private fun session(
        cipher: VaultBoundaryTestCipher,
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
