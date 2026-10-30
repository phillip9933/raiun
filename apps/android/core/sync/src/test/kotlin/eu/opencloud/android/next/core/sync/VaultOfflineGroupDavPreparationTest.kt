package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.nio.file.Files
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupDavPreparationTest {
    private val context = RuntimeEnvironment.getApplication()
    private val server = MockWebServer()
    private val material = ByteArray(80) { (it + 1).toByte() }
    private val vaultPath = "Secret.vault"
    private lateinit var cipher: VaultCipherEngine
    private lateinit var integrityToken: String
    private lateinit var collectionName: String
    private lateinit var rootFileName: String
    private lateinit var nestedFileName: String
    private lateinit var location: VaultLocation
    private lateinit var identity: VaultIdentity
    private lateinit var account: AccountEntity
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var session: VaultSession
    private lateinit var planRoot: File
    private lateinit var plans: VaultOfflineGroupPlanStore

    @Before
    fun setUp() =
        runBlocking {
            server.start()
            cipher = jvmRcloneVaultCipher(material).offlineEngine()
            integrityToken = cipher.createIntegrityToken()
            collectionName = cipher.encryptName("Collection")
            rootFileName = cipher.encryptName("Root file.bin")
            nestedFileName = cipher.encryptName("Nested file.bin")
            account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", false)
            location =
                VaultLocation(
                    account.id,
                    vaultPath,
                    VaultLocationKind.FOLDER_VAULT,
                    "drive",
                    "vault-id",
                    "source-root-id",
                    account.serverUrl,
                    server.url("dav/files/").toString(),
                    vaultPath,
                    true,
                )
            identity = VaultIdentity(account.id, account.serverUrl, "drive", "vault-id")
            database =
                Room
                    .inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java)
                    .allowMainThreadQueries()
                    .build()
            database.accountDao().upsert(account)
            store = FileBrowserStore(database)
            planRoot = Files.createTempDirectory(context.cacheDir.toPath(), "offline-group-dav-").toFile()
            plans = VaultOfflineGroupPlanStore(planRoot, jvmOfflineDurability(planRoot))

            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        if (request.method != "PROPFIND") return MockResponse().setResponseCode(405)
                        val relative =
                            request.requestUrl!!
                                .pathSegments
                                .drop(2)
                                .joinToString("/")
                        val body =
                            when (relative) {
                                vaultPath -> vaultListing(request.getHeader("Depth") == "1")
                                "$vaultPath/$collectionName" -> collectionListing()
                                else -> null
                            }
                        return if (body ==
                            null
                        ) {
                            MockResponse().setResponseCode(404)
                        } else {
                            MockResponse().setResponseCode(207).setBody(body)
                        }
                    }
                }

            val http = OkHttpClient()
            val access =
                VaultAccess(account, account.serverUrl, "Bearer synthetic", http, { true }) {
                    store.account(account.id)
                }
            session =
                VaultSession(
                    identity,
                    location,
                    cipher,
                    VaultDavClient(http, endpoints = EndpointPolicy(true)),
                    access,
                    { true },
                )
        }

    @After
    fun tearDown() {
        session.close()
        database.close()
        cipher.close()
        server.shutdown()
        planRoot.deleteRecursively()
        material.fill(0)
    }

    @Test
    fun realDavSaxRootCaptureKeepsAggregateDirectorySizesOutOfCiphertextTotals() =
        runBlocking {
            assertEquals(9_000L, sessionDavStat(vaultPath).size)
            val prepared = prepareGroup(path = "")
            assertEquals(2, prepared.fileCount)
            assertEquals(65_584L + 32L, prepared.ciphertextBytes)
            assertEquals(4, prepared.memberCount)
            assertTrue(prepared.members.any { it.source.relativePath == vaultPath && it.source.size == 9_000L })
            assertTrue(
                prepared.members.any {
                    it.source.relativePath == "$vaultPath/$collectionName" && it.source.size == 7_000L
                },
            )
            assertEquals(
                setOf("$vaultPath/$rootFileName", "$vaultPath/$collectionName/$nestedFileName"),
                prepared.jobs.map { it.source.relativePath }.toSet(),
            )
            assertEquals(setOf(65_584L, 32L), prepared.jobs.map { it.source.size }.toSet())
            assertTrue(server.requestCount >= 5)
        }

    @Test
    fun realDavSaxIssuedSubfolderCaptureKeepsItsAggregateSizeAndExactFileJob() =
        runBlocking {
            assertEquals(9_000L, sessionDavStat(vaultPath).size)
            val selected = session.list().single { it.isFolder }
            assertEquals("Collection", selected.name)
            assertEquals("$vaultPath/$collectionName", selected.encryptedPath)

            val prepared = prepareGroup(path = selected.path, selectedEntry = selected)
            assertEquals(1, prepared.fileCount)
            assertEquals(32L, prepared.ciphertextBytes)
            assertEquals(2, prepared.memberCount)
            assertEquals(
                7_000L,
                prepared.members
                    .first()
                    .source.size,
            )
            assertTrue(
                prepared.members
                    .first()
                    .source.isFolder,
            )
            assertEquals(
                "$vaultPath/$collectionName/$nestedFileName",
                prepared.jobs
                    .single()
                    .source.relativePath,
            )
            assertEquals(
                32L,
                prepared.jobs
                    .single()
                    .source.size,
            )
        }

    private suspend fun prepareGroup(
        path: String,
        selectedEntry: VaultFolder? = null,
    ): Prepared {
        val groups = store.vaultOfflineGroups()
        val owner = requireNotNull(groups.captureOwner(account.id))
        lateinit var acceptedId: String
        lateinit var frozen: VaultOfflineGroupContext
        session.withOfflineGroupSource(context, path, selectedEntry, additionalPermit = { true }) { source ->
            frozen =
                VaultOfflineGroupContext(
                    UUID.randomUUID().toString(),
                    owner,
                    identity,
                    location.copy(title = ""),
                    source.selected.relativePath,
                    source.rootProofDigest,
                    "a".repeat(64),
                )
            acceptedId = prepareVaultOfflineGroup(context, source, frozen, groups, plans) { true }.id
        }
        plans.open(owner, acceptedId).use { opaque ->
            val seal = opaque.seal
            opaque.verify(material, frozen).use { verified ->
                val members = mutableListOf<VaultOfflineGroupMember>()
                val jobs = mutableListOf<VaultDownloadJob>()
                verified.visitVerified { member ->
                    members += member
                    if (!member.source.isFolder) jobs += verified.fileJob(member)
                }
                return Prepared(
                    seal.memberCount.toInt(),
                    seal.fileCount.toInt(),
                    seal.ciphertextBytes,
                    members,
                    jobs,
                )
            }
        }
    }

    private fun sessionDavStat(path: String) =
        VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
            .statResource(location.rootWebDavUrl, path, "Bearer synthetic")

    private fun vaultListing(includeChildren: Boolean): String =
        multistatus(
            response(vaultPath, "vault-id", folder = true, size = 9_000L, integrity = integrityToken),
            *if (includeChildren) {
                arrayOf(
                    response("$vaultPath/$collectionName", "collection-id", true, 7_000L),
                    response("$vaultPath/$rootFileName", "root-file-id", false, 65_584L),
                )
            } else {
                emptyArray()
            },
        )

    private fun collectionListing(): String =
        multistatus(
            response("$vaultPath/$collectionName", "collection-id", true, 7_000L),
            response("$vaultPath/$collectionName/$nestedFileName", "nested-file-id", false, 32L),
        )

    private fun response(
        path: String,
        id: String,
        folder: Boolean,
        size: Long,
        integrity: String? = null,
    ): String {
        val href =
            server
                .url("dav/files/")
                .newBuilder()
                .addPathSegments(path)
                .apply { if (folder) addPathSegment("") }
                .build()
        val name = path.substringAfterLast('/')
        val type = if (folder) "<d:collection/>" else ""
        val contentLength = if (folder) "" else "<d:getcontentlength>$size</d:getcontentlength>"
        val proof = integrity?.let { "<ocrclone:integrity-id>$it</ocrclone:integrity-id>" }.orEmpty()
        return """
            <d:response>
              <d:href>$href</d:href>
              <d:propstat><d:prop>
                <d:resourcetype>$type</d:resourcetype>
                $contentLength<oc:size>$size</oc:size><d:getetag>"v1"</d:getetag>
                <oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$proof
              </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
            </d:response>
            """.trimIndent()
    }

    private fun multistatus(vararg responses: String) =
        """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">${responses.joinToString(
            "",
        )}</d:multistatus>"""

    private data class Prepared(
        val memberCount: Int,
        val fileCount: Int,
        val ciphertextBytes: Long,
        val members: List<VaultOfflineGroupMember>,
        val jobs: List<VaultDownloadJob>,
    )
}
