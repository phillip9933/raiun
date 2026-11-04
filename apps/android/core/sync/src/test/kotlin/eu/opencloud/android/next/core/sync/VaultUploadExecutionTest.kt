package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import kotlinx.coroutines.runBlocking
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
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
class VaultUploadExecutionTest {
    private val server = MockWebServer()
    private lateinit var database: FileBrowserDatabase
    private lateinit var repository: VaultRepository
    private lateinit var location: VaultLocation
    private val directory = Files.createTempDirectory("vault-upload-execution").toFile()
    private val payloads = VaultUploadStore(directory)
    private val bytes = ByteArray(96) { it.toByte() }
    private var remote: ByteArray? = null
    private var corruptRead = false
    private var token = "public-proof"
    private var downloadRange: String? = null
    private var wrongReadETag = false
    private var puts = 0
    private var revoked = false
    private var revokeOnPut = false
    private var hiddenDestinationListings = 0
    private var missingParentListings = 0
    private var noETagListings = 0
    private var rejectExistingOnPut = false
    private var expectedPutETag: String? = null
    private var extraChildren = ""
    private var invalidTail = ""
    private var remoteRootId = "vault-id"
    private val davDepths = mutableListOf<String>()
    private var honorRootDepthZero = false
    private var parentMemberScans = 0
    private var targetStats = 0
    private var targetStatBytes = 0L
    private var metadataBytes = 0L
    private var statFileId = "file-id"
    private var statTail = ""

    @Before fun prepare() {
        server.start()
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        val account = AccountEntity("account", server.url("/").toString().trimEnd('/'), "user", "User", "BASIC", false)
        runBlocking { database.accountDao().upsert(account) }
        repository =
            VaultRepository(
                FileBrowserStore(database),
                { "Bearer synthetic" },
                { OkHttpClient() },
                EndpointPolicy(true),
                { error("Background execution must never acquire an app unlock grant") },
            )
        location =
            VaultLocation(
                account.id,
                "",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault-id",
                "root",
                server.url("/").toString(),
                server.url("dav/files/").toString(),
                "public.vault",
                true,
            )
        server.dispatcher =
            object : Dispatcher() {
                @Suppress("ReturnCount") // One synthetic response per DAV/Graph request type.
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val path = request.path.orEmpty()
                    if (request.method == "PUT") {
                        puts++
                        if (revokeOnPut) revoked = true
                        if (expectedPutETag == null) {
                            assertEquals("*", request.getHeader("If-None-Match"))
                        } else {
                            assertEquals(expectedPutETag, request.getHeader("If-Match"))
                            assertEquals(null, request.getHeader("If-None-Match"))
                        }
                        if (rejectExistingOnPut && remote != null) return MockResponse().setResponseCode(412)
                        remote = request.body.readByteArray()
                        return MockResponse().setResponseCode(201)
                    }
                    if (request.method == "GET" && path.endsWith("enc-name")) {
                        assertEquals("\"tag-file-id\"", request.getHeader("If-Match"))
                        val body = requireNotNull(remote).copyOf()
                        if (corruptRead) body[40] = 99
                        downloadRange = request.getHeader("Range")
                        val offset = downloadRange?.removePrefix("bytes=")?.removeSuffix("-")?.toInt() ?: 0
                        val response =
                            MockResponse().setHeader(
                                "ETag",
                                if (wrongReadETag) "\"changed\"" else "\"tag-file-id\"",
                            )
                        if (offset >
                            0
                        ) {
                            response
                                .setResponseCode(
                                    206,
                                ).setHeader("Content-Range", "bytes $offset-${body.lastIndex}/${body.size}")
                        }
                        return response.setBody(Buffer().write(body.copyOfRange(offset, body.size)))
                    }
                    if (request.method == "PROPFIND") {
                        val depth = requireNotNull(request.getHeader("Depth"))
                        davDepths += depth
                        if (path == "/dav/files/public.vault/enc-name") return statResponse()
                        if (path.trimEnd('/') == "/dav/files/public.vault" && depth == "1") parentMemberScans++
                        val root =
                            if (path.trimEnd('/') == "/dav/files") {
                                entry("/dav/files/", "root", "files", true) +
                                    entry("/dav/files/public.vault/", "vault-id", "public.vault", true)
                            } else {
                                if (remote != null && missingParentListings > 0) {
                                    missingParentListings--
                                    return MockResponse().setResponseCode(404)
                                }
                                val hidden = remote != null && hiddenDestinationListings > 0
                                if (hidden) hiddenDestinationListings--
                                val noETag = remote != null && noETagListings > 0
                                if (noETag) noETagListings--
                                val hideSource = remote == null || hidden
                                val depthZero = honorRootDepthZero && depth == "0"
                                entry(
                                    "/dav/files/public.vault/",
                                    remoteRootId,
                                    "public.vault",
                                    true,
                                    "<ocrclone:integrity-id>$token</ocrclone:integrity-id>",
                                ) +
                                    if (hideSource || depthZero) {
                                        ""
                                    } else {
                                        entry(
                                            "/dav/files/public.vault/enc-name",
                                            "file-id",
                                            "enc-name",
                                            false,
                                            includeETag = !noETag,
                                        )
                                    }
                            }
                        val includeChildren = !honorRootDepthZero || depth != "0"
                        val extras =
                            if (path.trimEnd('/') == "/dav/files/public.vault" && includeChildren) {
                                extraChildren + invalidTail
                            } else {
                                ""
                            }
                        return metadataResponse(root + extras)
                    }
                    return MockResponse().setBody(
                        """{"value":[{"id":"drive","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"${server.url(
                            "dav/files/",
                        )}"}}]}""",
                    )
                }
            }
    }

    private fun metadataResponse(entries: String): MockResponse {
        val body =
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" " +
                "xmlns:ocrclone=\"ocrclone\">$entries</d:multistatus>"
        metadataBytes += body.toByteArray().size
        return MockResponse().setResponseCode(207).setBody(body)
    }

    private fun statResponse(): MockResponse {
        targetStats++
        if (remote == null) return MockResponse().setResponseCode(404)
        val before = metadataBytes
        // Hold the version constant so the replacement-ID test independently proves identity binding.
        val descriptor =
            entry("/dav/files/public.vault/enc-name", statFileId, "enc-name", false)
                .replace("<d:getetag>\"tag-$statFileId\"</d:getetag>", "<d:getetag>\"tag-file-id\"</d:getetag>")
        val response = metadataResponse(descriptor + statTail)
        targetStatBytes += metadataBytes - before
        return response
    }

    @After fun clean() {
        database.close()
        server.shutdown()
        directory.deleteRecursively()
    }

    @Test fun committedCiphertextUploadsWithoutUnlockGrantAndRequiresReadBackVerification() =
        runBlocking {
            val job = job()
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, false, {}, {}))
            assertEquals(1, puts)
        }

    @Test fun lostSuccessResponseReconcilesIdenticalCiphertextWithoutReupload() =
        runBlocking {
            val job = job()
            remote = bytes.copyOf()
            repository.executePreparedUpload(job, payloads, { true }, true, {}, {})
            assertEquals(0, puts)
        }

    @Test fun missingDestinationAfterPutWaitsForVisibilityThenVerifiesWithoutReplay() =
        runBlocking {
            val job = job()
            hiddenDestinationListings = 3
            val pending =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
                }
            assertTrue(pending.error is OpenCloudError.NotReady)
            assertEquals(1, puts)

            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, true, {}, {}))
            assertEquals(1, puts)
        }

    @Test fun missingParentAfterPutWaitsForServerProcessing() =
        runBlocking {
            val job = job()
            missingParentListings = 2
            val pending =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
                }
            assertTrue(pending.error is OpenCloudError.NotReady)
            val stillPending =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository.executePreparedUpload(job, payloads, { true }, true, {}, {}) }
                }
            assertTrue(stillPending.error is OpenCloudError.NotReady)
            assertEquals(1, puts)
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, true, {}, {}))
            assertEquals(1, puts)
        }

    @Test fun missingETagAfterPutWaitsForStrongVersion() =
        runBlocking {
            val job = job()
            noETagListings = 3
            val pending =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
                }
            assertTrue(pending.error is OpenCloudError.NotReady)
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, true, {}, {}))
            assertEquals(1, puts)
        }

    @Test fun conditionalRetryCollisionAcceptsOnlyIdenticalCommittedCiphertext() =
        runBlocking {
            val job = job()
            remote = bytes.copyOf()
            hiddenDestinationListings = 3
            rejectExistingOnPut = true
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, true, {}, {}))
            assertEquals(1, puts)
        }

    @Test fun conditionalRetryCollisionNeverAcceptsDifferentCiphertext() {
        val job = job()
        val other = ByteArray(bytes.size) { 42 }
        remote = other.copyOf()
        hiddenDestinationListings = 3
        rejectExistingOnPut = true
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { true }, true, {}, {}) }
            }
        assertEquals(OpenCloudError.Conflict, failure.error)
        assertEquals(1, puts)
        assertArrayEquals(other, remote)
    }

    @Test fun changedEncryptionProofFailsBeforeAnyMutation() {
        val job = job()
        token = "different-proof"
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, error.error)
        assertEquals(0, puts)
    }

    @Test fun corruptReadBackCannotBecomeSuccessfulTransfer() {
        val job = job()
        corruptRead = true
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
            }
        assertEquals(OpenCloudError.InvalidResponse, error.error)
        assertEquals(1, puts)
    }

    @Test fun revokedAccountPermitFailsBeforeServerMutation() {
        val job = job()
        assertThrows(OpenCloudException::class.java) {
            runBlocking { repository.executePreparedUpload(job, payloads, { false }, false, {}, {}) }
        }
        assertEquals(0, puts)
    }

    @Test fun revocationAfterRemoteCommitCannotReportSuccess() {
        val job = job()
        revokeOnPut = true
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { !revoked }, false, {}, {}) }
            }
        assertEquals(OpenCloudError.AccessDenied, error.error)
        assertEquals(1, puts)
        assertEquals(job, payloads.read(job.id))
    }

    @Test fun ciphertextDownloadCompletesTransportWithoutAnyUnlockGrant() =
        runBlocking {
            remote = bytes.copyOf()
            val (store, job) = downloadJob()
            assertEquals(bytes.size.toLong(), repository.executePreparedDownload(job, store, { true }, {}))
            org.junit.Assert.assertArrayEquals(bytes, store.partial(job).readBytes())
            assertEquals(0, puts)
        }

    @Test fun preparedDownloadsStatOnlyTheirTargetAndMetadataStaysLinearWithWideParents() =
        runBlocking {
            remote = bytes.copyOf()
            honorRootDepthZero = true
            extraChildren =
                (0 until 7000).joinToString("") { n ->
                    entry("/dav/files/public.vault/opaque-$n", "extra-$n", "opaque-$n", false)
                }
            assertTrue(extraChildren.toByteArray().size > 2 * 1024 * 1024)
            val (firstStore, first) = downloadJob()
            repository.executePreparedDownload(first, firstStore, { true }, {})
            val oneMetadataCost = metadataBytes
            repeat(3) {
                val (store, job) = downloadJob()
                repository.executePreparedDownload(job, store, { true }, {})
                assertArrayEquals(bytes, store.partial(job).readBytes())
            }
            assertEquals(0, parentMemberScans)
            assertEquals(4, targetStats)
            assertEquals(4 * oneMetadataCost, metadataBytes)
            assertTrue(targetStatBytes < 4 * 2_048)
            assertTrue(metadataBytes < 4 * 20_000)
            assertEquals(0, puts)
        }

    @Test fun changedExactStatIdentityRefusesCiphertextBeforeGet() {
        remote = bytes.copyOf()
        val (store, job) = downloadJob()
        statFileId = "replacement-file-id"
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedDownload(job, store, { true }, {}) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(null, downloadRange)
        assertEquals(0, puts)
    }

    @Test fun extraResourceAfterValidTargetStatCannotTriggerCiphertextGet() {
        remote = bytes.copyOf()
        val (store, job) = downloadJob()
        statTail = entry("/dav/files/public.vault/sibling", "sibling-id", "sibling", false)
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedDownload(job, store, { true }, {}) }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(null, downloadRange)
        assertEquals(0, puts)
    }

    @Test fun ciphertextDownloadResumesOnlyTheCapturedStrongVersion() =
        runBlocking {
            remote = bytes.copyOf()
            val (store, job) = downloadJob()
            val source = job.source
            val identity =
                "${location.accountId}|${location.canonicalServer}|${location.driveId}|" +
                    "${location.remoteVaultId}|${source.id}|${source.relativePath}|${source.size}|${source.strongETag}"
            prepareDownloadCheckpoint(store.partial(job), store.checkpoint(job), identity, source.size, true)
            store.partial(job).writeBytes(bytes.copyOfRange(0, 20))
            repository.executePreparedDownload(job, store, { true }, {})
            assertEquals("bytes=20-", downloadRange)
            org.junit.Assert.assertArrayEquals(bytes, store.partial(job).readBytes())
        }

    @Test fun substitutedDownloadResponseCannotCompleteCapturedVersion() {
        remote = bytes.copyOf()
        wrongReadETag = true
        val (store, job) = downloadJob()
        assertThrows(OpenCloudException::class.java) {
            runBlocking { repository.executePreparedDownload(job, store, { true }, {}) }
        }
        assertEquals(0, puts)
    }

    @Test fun changedRootProofRejectsDownloadBeforeFetchingCiphertext() {
        remote = bytes.copyOf()
        val (store, job) = downloadJob()
        token = "changed-proof"
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedDownload(job, store, { true }, {}) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, error.error)
        assertEquals(null, downloadRange)
    }

    @Test fun largeRootUploadAndDownloadKeepCapturedVersionsAndProofs() =
        runBlocking {
            extraChildren =
                (0 until 7000).joinToString("") { number ->
                    entry("/dav/files/public.vault/opaque-$number", "extra-$number", "opaque-$number", false)
                }
            assertTrue(extraChildren.toByteArray().size > 2 * 1024 * 1024)
            val upload = job()
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(upload, payloads, { true }, false, {}, {}))
            val (downloads, download) = downloadJob()
            assertEquals(bytes.size.toLong(), repository.executePreparedDownload(download, downloads, { true }, {}))
            assertArrayEquals(bytes, downloads.partial(download).readBytes())
            assertEquals(1, puts)
            assertEquals(setOf("0", "1"), davDepths.toSet())
        }

    @Test fun lateDuplicateRejectsLargeRootBeforeUploadOrCiphertextDownload() {
        remote = bytes.copyOf()
        extraChildren =
            (0 until 7000).joinToString("") { number ->
                entry("/dav/files/public.vault/opaque-$number", "extra-$number", "opaque-$number", false)
            }
        invalidTail = entry("/dav/files/public.vault/duplicate", "extra-0", "duplicate", false)
        val upload = job()
        assertThrows(OpenCloudException::class.java) {
            runBlocking { repository.executePreparedUpload(upload, payloads, { true }, false, {}, {}) }
        }
        val (downloads, download) = downloadJob()
        assertThrows(OpenCloudException::class.java) {
            runBlocking { repository.executePreparedDownload(download, downloads, { true }, {}) }
        }
        assertEquals(0, puts)
        assertEquals(null, downloadRange)
    }

    @Test fun streamedRootIdentityReplacementFailsBeforeMutation() {
        remoteRootId = "replacement-vault-id"
        val upload = job()
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(upload, payloads, { true }, false, {}, {}) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(0, puts)
    }

    private fun downloadJob(): Pair<VaultDownloadStore, VaultDownloadJob> {
        val store = VaultDownloadStore(java.io.File(directory, "downloads"))
        val source =
            VaultDavEntry(
                "file-id",
                "public.vault/enc-name",
                "enc-name",
                false,
                bytes.size.toLong(),
                "\"tag-file-id\"",
                server.url("dav/files/public.vault/enc-name").toString(),
            )
        val job = store.create(location, source, vaultProofDigest("public-proof"))
        check(store.finishPrepared(job.id) { true })
        return store to job
    }

    @Test fun replacementUsesCapturedETagAndVerifiesAllCommittedCiphertext() =
        runBlocking {
            remote = ByteArray(bytes.size) { 42 }
            expectedPutETag = "\"tag-file-id\""
            val job = job(expectedPutETag)
            assertEquals(expectedPutETag, repository.executePreparedUpload(job, payloads, { true }, false, {}, {}))
            assertEquals(1, puts)
            assertArrayEquals(bytes, remote)
            assertEquals(null, downloadRange)
        }

    @Test fun replacementNeverFetchesAFreshETagToOverwriteAnotherVersion() {
        remote = ByteArray(bytes.size) { 42 }
        val job = job("\"old-version\"")
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { true }, false, {}, {}) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(0, puts)
        assertArrayEquals(ByteArray(bytes.size) { 42 }, remote)
    }

    @Test fun replacementLostResponseRecoveryRequiresMatchingCiphertextAndStrongReadVersion() =
        runBlocking {
            remote = bytes.copyOf()
            val job = job("\"original-version\"")
            assertEquals("\"tag-file-id\"", repository.executePreparedUpload(job, payloads, { true }, true, {}, {}))
            assertEquals(0, puts)
            wrongReadETag = true
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository.executePreparedUpload(job, payloads, { true }, true, {}, {}) }
            }
            assertEquals(0, puts)
        }

    private fun job(expectedETag: String? = null): VaultUploadJob =
        payloads
            .prepare(location, "public.vault/enc-name", expectedETag, vaultProofDigest("public-proof")) {
                it.write(bytes)
            }.also { check(payloads.finishPrepared(it.id) { true }) }

    @Suppress("LongParameterList") // DAV fixture needs explicit identity, type, proof, and version fields.
    private fun entry(
        path: String,
        id: String,
        name: String,
        folder: Boolean,
        proof: String = "",
        includeETag: Boolean = true,
    ): String =
        """<d:response><d:href>$path</d:href><d:propstat><d:prop><d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype><d:getcontentlength>${if (folder) 0 else bytes.size}</d:getcontentlength>${if (includeETag) "<d:getetag>\"tag-$id\"</d:getetag>" else ""}<oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$proof</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
}
