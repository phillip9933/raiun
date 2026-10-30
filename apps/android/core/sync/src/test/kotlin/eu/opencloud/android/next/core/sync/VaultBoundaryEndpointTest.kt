package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
class VaultBoundaryEndpointTest {
    @Test fun `encrypted folder cleanup refuses a new child version after its empty proof`() {
        MockWebServer().use { server ->
            var added = false
            val deletions = AtomicInteger()
            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse =
                        when {
                            request.method == "DELETE" -> {
                                deletions.incrementAndGet()
                                MockResponse().setResponseCode(204)
                            }
                            request.path
                                .orEmpty()
                                .trimEnd('/')
                                .endsWith("/encoded-Folder") -> {
                                added = true
                                listing("/dav/Secret.vault/encoded-Folder/", "folder", "before")
                            }
                            else ->
                                listing(
                                    "/dav/Secret.vault/",
                                    "vault",
                                    "root",
                                    response(
                                        "/dav/Secret.vault/encoded-Folder/",
                                        "folder",
                                        if (added) "after" else "before",
                                    ),
                                )
                        }
                }
            server.start()
            val account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", false)
            val location =
                VaultLocation(
                    "account",
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
                VaultAccess(account, account.serverUrl, "Bearer synthetic", OkHttpClient(), { true }, { account })
            VaultSession(
                VaultIdentity(
                    "account",
                    account.serverUrl,
                    "drive",
                    "vault",
                ),
                location,
                NamesCipher(),
                VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true)),
                access,
                {
                    true
                },
            ).use { session ->
                val endpoint = VaultBoundaryEndpoint(session, location)
                val error =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking {
                            endpoint.delete(
                                BoundaryEntry("folder", "Folder", "Folder", true, 0, "\"before\""),
                            )
                        }
                    }
                assertEquals(OpenCloudError.PreconditionFailed, error.error)
                assertEquals(0, deletions.get())
            }
        }
    }

    private fun listing(
        path: String,
        id: String,
        version: String,
        children: String = "",
    ): MockResponse =
        MockResponse()
            .setResponseCode(
                207,
            ).setBody(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" " +
                    "xmlns:crypt=\"ocrclone\">${response(path, id, version)}$children</d:multistatus>",
            )

    private fun response(
        path: String,
        id: String,
        version: String,
    ): String =
        "<d:response><d:href>$path</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>" +
            "<d:getcontentlength>0</d:getcontentlength><d:getetag>\"$version\"</d:getetag><oc:fileid>$id</oc:fileid>" +
            (if (id == "vault") "<crypt:integrity-id>proof</crypt:integrity-id>" else "") +
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

    private class NamesCipher : VaultCipherEngine {
        override fun createIntegrityToken() = "proof"

        override fun verifyIntegrityToken(base64Token: String) = base64Token == "proof"

        override fun encryptName(plain: String) = "encoded-$plain"

        override fun decryptName(encrypted: String) = encrypted.removePrefix("encoded-")

        override fun encryptPath(plain: String) =
            plain.split('/').filter(String::isNotEmpty).joinToString("/") {
                encryptName(it)
            }

        override fun decryptPath(encrypted: String) =
            encrypted.split('/').filter(String::isNotEmpty).joinToString("/") {
                decryptName(it)
            }

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long = error("Unused fixture operation")

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long = error("Unused fixture operation")

        override fun exportKeyMaterial() = ByteArray(32)

        override fun close() = Unit
    }
}
