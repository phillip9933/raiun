package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bounded local production-pipeline observations, not a phone/live-server or old/current benchmark.
 * Real rclone material initialization, authenticated token verification and names use the existing host
 * Sodium seam. Room, DAV parsing, private encrypted directory staging and page leases are real.
 * Synthetic already-unwrapped material excludes Android Keystore/biometric and remembered-key IO.
 * Response-header delay is per request; it is a controlled latency model, not measured network RTT.
 * There are deliberately no elapsed-time assertions. One warmup precedes three recorded samples.
 */
@RunWith(RobolectricTestRunner::class)
class VaultUnlockTimingTest {
    private val material = ByteArray(80) { (it + 1).toByte() }
    private val http = OkHttpClient.Builder().callTimeout(10, TimeUnit.SECONDS).build()
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var account: AccountEntity
    private lateinit var store: FileBrowserStore
    private lateinit var spool: File
    private lateinit var integrityToken: String
    private lateinit var encryptedNames: List<String>
    private val plainNames = List(50) { "Photo-${it.toString().padStart(3, '0')}.jpg" }

    @Before
    fun setUp() =
        runBlocking {
            server = MockWebServer().also { it.start() }
            val context = RuntimeEnvironment.getApplication()
            database =
                Room
                    .inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java)
                    .allowMainThreadQueries()
                    .build()
            store = FileBrowserStore(database)
            account = AccountEntity("timing", server.url("/").toString().trimEnd('/'), "user", "User", "BASIC", false)
            database.accountDao().upsert(account)
            spool = Files.createTempDirectory(context.cacheDir.toPath(), "vault-unlock-timing-").toFile()
            jvmRcloneVaultCipher(material).use { cipher ->
                integrityToken = cipher.createIntegrityToken()
                encryptedNames = plainNames.map(cipher::encryptName)
            }
        }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
        http.connectionPool.evictAll()
        http.dispatcher.executorService.shutdown()
        spool.deleteRecursively()
        material.fill(0)
    }

    @Test
    fun rememberedMaterialProductionPipelineHasBoundedLocalPhaseObservations() =
        runBlocking {
            for (folder in listOf(false, true)) {
                for (count in listOf(0, 50)) {
                    for (delayMillis in listOf(0L, 40L)) {
                        val scenario = Scenario(folder, count, delayMillis)
                        configureServer(scenario)
                        repeat(4) { sample -> observe(scenario, sample) }
                    }
                }
            }
        }

    @Test
    fun wrongRememberedMaterialCannotOpenEvenAnEmptyDirectory() =
        runBlocking {
            val scenario = Scenario(folder = false, count = 0, delayMillis = 0)
            configureServer(scenario)
            val wrongMaterial = ByteArray(80) { (it + 2).toByte() }
            try {
                val repository = repository(AtomicBoolean(true)) {}
                val failure =
                    assertThrows(VaultUnlockException::class.java) {
                        runBlocking {
                            repository.unlockWithKeyMaterial(
                                account.id,
                                location(scenario),
                                keyMaterial = wrongMaterial,
                            )
                        }
                    }
                assertEquals(VaultUnlockFailure.PASSWORD_NOT_PROVEN, failure.failure)
                assertRequests(scenario, listOf(null, "1"))
            } finally {
                wrongMaterial.fill(0)
            }
        }

    private suspend fun observe(
        scenario: Scenario,
        sample: Int,
    ) {
        val permit = AtomicBoolean(true)
        var codecInitializationNanos = 0L
        val repository = repository(permit) { codecInitializationNanos = it }
        val started = System.nanoTime()
        repository.unlockWithKeyMaterial(account.id, location(scenario), keyMaterial = material).use { session ->
            val verified = System.nanoTime()
            session.openDirectory().use { snapshot ->
                val opened = System.nanoTime()
                val page = snapshot.page(limit = 128)
                val admitted = System.nanoTime()
                assertEquals(scenario.count.toLong(), snapshot.totalCount)
                assertEquals(plainNames.take(scenario.count), page.map { it.name })
                assertEquals(plainNames.take(scenario.count), page.map { it.path })
                assertTrue(page.all { !it.isFolder && it.leaseId != null && it.rawName != it.name })
                assertRequests(
                    scenario,
                    if (scenario.folder) listOf(null, "0", "1", "0", "1", "0") else listOf(null, "1", "0", "1", "0"),
                )
                if (sample > 0) {
                    emit(scenario, sample, "codec_material_initialization", codecInitializationNanos, 0)
                    // Inclusive unlock includes codec material initialization, Graph authorization/root binding,
                    // DAV proof retrieval and authenticated token verification; no subtraction.
                    emit(
                        scenario,
                        sample,
                        "repository_unlock_inclusive",
                        verified - started,
                        if (scenario.folder) 3 else 2,
                    )
                    emit(scenario, sample, "directory_open", opened - verified, 3)
                    emit(scenario, sample, "snapshot_page_admission", admitted - opened, 0)
                }
                permit.set(false)
                assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
                assertEquals(0, server.requestCount - consumedRequests)
            }
        }
        assertFalse(spool.listFiles().orEmpty().any { it.name.startsWith("vault-directory-") })
    }

    private fun repository(
        permit: AtomicBoolean,
        onCodecInitialization: (Long) -> Unit,
    ): VaultRepository =
        VaultRepository(
            store = store,
            authorizationFor = { "Bearer synthetic" },
            clientFor = { http },
            endpointPolicy = EndpointPolicy(true),
            permitFor = { { permit.get() } },
            cipherFactories =
                VaultCipherFactories(
                    password = { error("Timing fixture must use already-unwrapped remembered material") },
                    keyMaterial = {
                        val started = System.nanoTime()
                        jvmRcloneVaultCipher(it).asVaultCipher().also {
                            onCodecInitialization(
                                System.nanoTime() - started,
                            )
                        }
                    },
                ),
            spoolDirectory = spool,
        )

    private fun location(scenario: Scenario): VaultLocation =
        VaultLocation(
            account.id,
            "Timing.vault",
            if (scenario.folder) VaultLocationKind.FOLDER_VAULT else VaultLocationKind.SPACE_VAULT,
            "drive",
            if (scenario.folder) "vault-id" else "root",
            "root",
            server.url("/").toString(),
            server.url("dav/files/").toString(),
            if (scenario.folder) "Timing.vault" else "",
            true,
        )

    private fun configureServer(scenario: Scenario) {
        val location = location(scenario)
        val rootPath = "/dav/files/${location.vaultPath}".trimEnd('/')
        val graphBody =
            """{"value":[{"id":"drive","name":"Timing.vault","driveType":"${if (scenario.folder) "personal" else "project"}",${
                if (scenario.folder) "" else "\"@libre.graph.contentType\":\"application/vnd.opencloud.vault\","
            }"root":{"id":"root","webDavUrl":"${location.rootWebDavUrl}"}}]}"""
        val root = davEntry(rootPath, location.remoteVaultId, "Timing.vault", folder = true, integrity = integrityToken)
        val children =
            encryptedNames.take(scenario.count).mapIndexed {
                index,
                name,
                ->
                davEntry("$rootPath/$name", "file-$index", name)
            }
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val response =
                        when {
                            request.method == "GET" && request.path == "/graph/v1.0/me/drives" ->
                                MockResponse()
                                    .setBody(
                                        graphBody,
                                    )
                            request.method == "PROPFIND" && request.path?.trimEnd('/') == rootPath ->
                                MockResponse().setResponseCode(207).setBody(
                                    """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">$root${
                                        if (request.getHeader("Depth") == "1") children.joinToString("") else ""
                                    }</d:multistatus>""",
                                )
                            else -> MockResponse().setResponseCode(404)
                        }
                    return response.setHeadersDelay(scenario.delayMillis, TimeUnit.MILLISECONDS)
                }
            }
    }

    private var consumedRequests = 0

    private fun assertRequests(
        scenario: Scenario,
        depths: List<String?>,
    ) {
        assertEquals(depths.size, server.requestCount - consumedRequests)
        depths.forEachIndexed { index, depth ->
            val request = requireNotNull(server.takeRequest(1, TimeUnit.SECONDS))
            assertEquals("Bearer synthetic", request.getHeader("Authorization"))
            assertEquals(if (index == 0) "GET" else "PROPFIND", request.method)
            assertEquals(
                if (index ==
                    0
                ) {
                    "/graph/v1.0/me/drives"
                } else if (scenario.folder) {
                    "/dav/files/Timing.vault"
                } else {
                    "/dav/files/"
                },
                request.path,
            )
            assertEquals(depth, request.getHeader("Depth"))
            consumedRequests++
        }
    }

    private fun davEntry(
        path: String,
        id: String,
        name: String,
        folder: Boolean = false,
        integrity: String? = null,
    ): String =
        """<d:response><d:href>$path${if (folder) "/" else ""}</d:href><d:propstat><d:prop>
        <d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype><d:getcontentlength>${if (folder) 0 else 65584}</d:getcontentlength>
        <d:getetag>"tag-$id"</d:getetag><oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>
        ${integrity?.let { "<ocrclone:integrity-id>$it</ocrclone:integrity-id>" }.orEmpty()}
        </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""

    private fun emit(
        scenario: Scenario,
        sample: Int,
        phase: String,
        elapsedNanos: Long,
        requests: Int,
    ) {
        println(
            "VAULT_UNLOCK_LOCAL_TIMING scenario=${if (scenario.folder) "folder" else "space"}" +
                " files=${scenario.count} response_delay_ms=${scenario.delayMillis} sample=$sample" +
                " phase=$phase elapsed_ns=$elapsedNanos requests=$requests",
        )
    }

    private data class Scenario(
        val folder: Boolean,
        val count: Int,
        val delayMillis: Long,
    )
}
