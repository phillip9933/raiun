package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class VaultOfflinePinDispatcherTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var accountStore: FileBrowserStore
    private lateinit var account: AccountEntity

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        accountStore = FileBrowserStore(database)
        account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", false)
        runBlocking { database.accountDao().upsert(account) }
    }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
    }

    @Test
    fun filePinPerformsDavRevalidationOffCallerThreadAndOpensSavedSnapshot() =
        runBlocking {
            val callerThread = Thread.currentThread()
            val requestThread = AtomicReference<Thread>()
            val http =
                OkHttpClient
                    .Builder()
                    .eventListenerFactory {
                        object : EventListener() {
                            override fun callStart(call: Call) {
                                requestThread.set(Thread.currentThread())
                            }
                        }
                    }.build()
            val cipher = PinTestCipher()
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
            val identity = VaultIdentity(account.id, account.serverUrl, "drive", "vault-id")
            val access =
                VaultAccess(
                    account,
                    account.serverUrl,
                    "Bearer test",
                    http,
                    { true },
                    { accountStore.account(account.id) },
                )
            val session =
                VaultSession(
                    identity,
                    location,
                    cipher,
                    VaultDavClient(http, endpoints = EndpointPolicy(true)),
                    access,
                    { true },
                )
            val offlineRoot = Files.createTempDirectory("vault-pin-dispatch").toFile()
            val plaintext = "offline payload".toByteArray()
            val ciphertext = PinTestCipher.ciphertext(plaintext)
            val offline =
                VaultOfflineStore(
                    offlineRoot,
                    { accountStore.account(it) },
                    { { true } },
                    EndpointPolicy(true),
                    { PinTestCipher() },
                )
            repeat(4) { server.enqueue(rootListing(ciphertext.size)) }
            server.enqueue(MockResponse().setBody(Buffer().write(ciphertext)))
            try {
                val entry = session.list().single()
                requestThread.set(null)
                session.pinOffline(offline, entry)
                val saved = session.offlineFiles(offline, "").single()
                assertEquals(entry.encryptedPath, saved.encryptedPath)
                assertEquals(entry.strongETag, saved.strongETag)

                assertNotSame(callerThread, requestThread.get())
                val cached = offline.openWithKeyMaterial(account.id, location, ByteArray(80))!!
                try {
                    val listed = cached.list().single()
                    assertEquals("offline.txt", listed.name)
                    val output = ByteArrayOutputStream()
                    cached.download(listed, output)
                    assertArrayEquals(plaintext, output.toByteArray())
                } finally {
                    cached.close()
                }
                repeat(4) {
                    assertEquals("PROPFIND", server.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!.method)
                }
                val get = server.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!
                assertEquals("GET", get.method)
                assertEquals("\"file-etag\"", get.getHeader("If-Match"))
            } finally {
                session.close()
                offlineRoot.deleteRecursively()
                plaintext.fill(0)
                ciphertext.fill(0)
            }
        }

    private fun rootListing(ciphertextSize: Int): MockResponse =
        MockResponse().setResponseCode(207).setBody(
            """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/files/Secret.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-etag"</d:getetag><oc:fileid>vault-id</oc:fileid><oc:name>Secret.vault</oc:name></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/files/Secret.vault/offline.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>$ciphertextSize</d:getcontentlength><d:getetag>"file-etag"</d:getetag><oc:fileid>file-id</oc:fileid><oc:name>offline.txt</oc:name></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
        )

    private class PinTestCipher : VaultCipherEngine {
        override fun createIntegrityToken() = "proof"

        override fun verifyIntegrityToken(base64Token: String) = base64Token == "proof"

        override fun decryptName(encrypted: String) = encrypted

        override fun decryptPath(encrypted: String) = encrypted

        override fun encryptName(plain: String) = plain

        override fun encryptPath(plain: String) = plain

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = 0L

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            val bytes = input.readBytes()
            require(
                bytes.size >= 48 &&
                    bytes.take(32).all { it == 7.toByte() } &&
                    bytes.takeLast(16).all { it == 9.toByte() },
            )
            val plain = bytes.copyOfRange(32, bytes.size - 16)
            output.write(plain)
            plain.fill(0)
            bytes.fill(0)
            return plain.size.toLong()
        }

        override fun exportKeyMaterial() = ByteArray(80)

        override fun close() = Unit

        companion object {
            fun ciphertext(plain: ByteArray) = ByteArray(32) { 7 } + plain + ByteArray(16) { 9 }
        }
    }
}
