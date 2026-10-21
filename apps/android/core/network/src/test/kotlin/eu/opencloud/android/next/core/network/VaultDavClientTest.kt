package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class VaultDavClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: VaultDavClient

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `production rejects cleartext endpoints before transmitting credentials`() {
        assertThrows(OpenCloudException::class.java) {
            VaultDavClient(
                OkHttpClient(),
            ).list(server.url("dav/Vault.vault/").toString(), authorization = "Bearer test")
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun `graph recognized vault root can lack a proof token but must be a collection`() {
        for (folder in listOf(true, false)) {
            server.enqueue(
                MockResponse().setResponseCode(207).setBody(envelope(response("/dav/space/", "root", "space", folder))),
            )
            if (folder) {
                val listing =
                    client.list(
                        server.url("dav/space/").toString(),
                        authorization = "Bearer test",
                        recognizedVaultRoot = true,
                    )
                assertEquals(true, listing.vaultEvidence)
                assertNull(listing.integrityToken)
            } else {
                assertThrows(OpenCloudException::class.java) {
                    client.list(
                        server.url("dav/space/").toString(),
                        authorization = "Bearer test",
                        recognizedVaultRoot = true,
                    )
                }
            }
        }
    }

    @Test fun `full ciphertext response must match listed size`() {
        server.enqueue(MockResponse().setBody("short"))
        val entry =
            VaultDavEntry("id", "cipher", "cipher", false, 64, null, server.url("dav/Vault.vault/cipher").toString())
        assertThrows(OpenCloudException::class.java) {
            client.readCiphertext(server.url("dav/Vault.vault/").toString(), entry, "Bearer test")
        }
    }

    @Test fun `vault listing preserves encrypted names identities integrity namespace and strong etags`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response(
                        "/dav/Secret.vault/",
                        "root-1",
                        "Secret.vault",
                        true,
                        "<c:integrity-id xmlns:c=\"ocrclone\">proof-token</c:integrity-id>",
                    ),
                    response("/dav/Secret.vault/encdir", "child-1", "encdir", true, "", "W/\"weak\""),
                    response("/dav/Secret.vault/enc%2Bname", "child-2", "enc+name", false, "", "\"strong\"", 65_584),
                ),
            ),
        )

        val listing = client.list(server.url("dav/Secret.vault/").toString(), authorization = "Bearer secret")

        assertEquals("root-1", listing.root.id)
        assertEquals("Secret.vault", listing.root.rawName)
        assertEquals(true, listing.vaultEvidence)
        assertEquals("proof-token", listing.integrityToken)
        assertEquals(listOf("encdir", "enc+name"), listing.children.map { it.rawName })
        assertEquals(listOf("encdir", "enc+name"), listing.children.map { it.relativePath })
        assertEquals(65_584L, listing.children.last().size)
        assertNull(listing.children.first().strongETag)
        assertEquals("\"strong\"", listing.children.last().strongETag)
        val request = server.takeRequest()
        assertEquals("PROPFIND", request.method)
        assertEquals("1", request.getHeader("Depth"))
        assertEquals("Bearer secret", request.getHeader("Authorization"))
        assert(request.body.readUtf8().contains("xmlns:ocrclone=\"ocrclone\""))
    }

    @Test fun `proof namespace may establish a vault root without a clear suffix`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response(
                        "/dav/space/",
                        "space-1",
                        "space",
                        true,
                        "<v:integrity-id xmlns:v=\"ocrclone\">opaque</v:integrity-id>",
                    ),
                ),
            ),
        )
        val listing = client.list(server.url("dav/space/").toString(), authorization = "Bearer test")
        assertEquals(true, listing.vaultEvidence)
        assertEquals("opaque", listing.integrityToken)
    }

    @Test fun `ordinary parent discovery returns only vault folders and preserves nonzero folder size`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response("/dav/files/", "parent", "files", true, ""),
                    response("/dav/files/Project.vault", "vault", "Project.vault", true, "", size = 42),
                    response("/dav/files/notes.txt", "file", "notes.txt", false, "", size = 19),
                    response("/dav/files/archive.vault", "vault-file", "archive.vault", false, "", size = 16),
                ),
            ),
        )

        val found = client.discoverFolderVaults(server.url("dav/files/").toString(), authorization = "Bearer test")

        assertEquals(listOf("Project.vault"), found.map { it.rawName })
        assertEquals(42L, found.single().size)
    }

    @Test fun `ordinary parent discovery exposes explicit vault folder markers`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response("/dav/files/", "parent", "files", true, ""),
                    response(
                        "/dav/files/hidden-vault",
                        "vault",
                        "hidden-vault",
                        true,
                        "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                    ),
                    response("/dav/files/plain", "plain", "plain", true, ""),
                ),
            ),
        )

        val found = client.discoverFolderVaults(server.url("dav/files/").toString(), authorization = "Bearer test")

        assertEquals(listOf("hidden-vault"), found.map { it.rawName })
        assertEquals(true, found.single().isVaultMarker)
    }

    @Test fun `names retain significant whitespace`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response(
                        "/dav/Secret.vault/",
                        "root",
                        "Secret.vault",
                        true,
                        "<v:integrity-id xmlns:v=\"ocrclone\">proof</v:integrity-id>",
                    ),
                    response("/dav/Secret.vault/%20cipher%20", "spaced", " cipher ", false, "", size = 7),
                ),
            ),
        )

        val item =
            client
                .list(
                    server.url("dav/Secret.vault/").toString(),
                    authorization = "Bearer test",
                ).children
                .single()

        assertEquals(" cipher ", item.rawName)
        assertEquals(" cipher ", item.relativePath)
    }

    @Test fun `listing rejects a non vault root and malicious hrefs`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response("/dav/plain/", "plain-1", "plain", true, ""),
                ),
            ),
        )
        val unsupported =
            assertThrows(OpenCloudException::class.java) {
                client.list(server.url("dav/plain/").toString(), authorization = "Bearer test")
            }
        assertEquals(OpenCloudError.Unsupported, unsupported.error)

        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response("https://attacker.example/dav/Secret.vault/", "root", "Secret.vault", true, ""),
                ),
            ),
        )
        val invalid =
            assertThrows(OpenCloudException::class.java) {
                client.list(server.url("dav/Secret.vault/").toString(), authorization = "Bearer secret")
            }
        assertEquals(OpenCloudError.InvalidResponse, invalid.error)
    }

    @Test fun `redirect is rejected and credentials are not forwarded`() {
        val target = MockWebServer().also { it.start() }
        try {
            server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", target.url("dav/")))
            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.list(server.url("dav/Secret.vault/").toString(), authorization = "Bearer secret")
                }
            assertEquals(302, failure.statusCode)
            assertEquals("Bearer secret", server.takeRequest().getHeader("Authorization"))
            assertEquals(0, target.requestCount)
        } finally {
            target.shutdown()
        }
    }

    @Test fun `ciphertext read is scoped bounded and uses raw encoded path`() {
        val bytes = byteArrayOf(0, 1, 2, 3)
        server.enqueue(MockResponse().setBody(okio.Buffer().write(bytes)))
        val entry =
            VaultDavEntry(
                "id",
                "enc+name",
                "enc+name",
                false,
                4,
                "\"v1\"",
                server.url("dav/Vault.vault/enc%2Bname").toString(),
            )

        val read = client.readCiphertext(server.url("dav/Vault.vault/").toString(), entry, "Bearer secret")

        assertArrayEquals(bytes, read)
        val request = server.takeRequest()
        assertEquals("/dav/Vault.vault/enc%2Bname", request.path)
        assertEquals("Bearer secret", request.getHeader("Authorization"))
        assertNull(request.getHeader("Range"))
        assertEquals("\"v1\"", request.getHeader("If-Match"))
    }

    @Test fun `proof prefix request is bounded even if range is ignored`() {
        val body = ByteArray(65_585) { 7 }
        server.enqueue(MockResponse().setBody(okio.Buffer().write(body)))
        val entry =
            VaultDavEntry(
                "id",
                "cipher",
                "cipher",
                false,
                body.size.toLong(),
                null,
                server.url("dav/Vault.vault/cipher").toString(),
            )
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client.readProofPrefix(server.url("dav/Vault.vault/").toString(), entry, "Bearer secret")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals("bytes=0-65583", server.takeRequest().getHeader("Range"))
    }

    @Test fun `proof prefix accepts a valid partial response and validates Content Range`() {
        val body = byteArrayOf(1, 2, 3, 4)
        val entry =
            VaultDavEntry("id", "cipher", "cipher", false, 4, null, server.url("dav/Vault.vault/cipher").toString())
        server.enqueue(MockResponse().setResponseCode(200).setBody(okio.Buffer().write(body)))

        assertArrayEquals(body, client.readProofPrefix(server.url("dav/Vault.vault/").toString(), entry, "Bearer test"))

        server.enqueue(
            MockResponse()
                .setResponseCode(
                    206,
                ).addHeader("Content-Range", "bytes 0-3/4")
                .setBody(okio.Buffer().write(body)),
        )

        assertArrayEquals(body, client.readProofPrefix(server.url("dav/Vault.vault/").toString(), entry, "Bearer test"))

        server.enqueue(
            MockResponse()
                .setResponseCode(
                    206,
                ).addHeader("Content-Range", "bytes 1-4/5")
                .setBody(okio.Buffer().write(body)),
        )
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client.readProofPrefix(server.url("dav/Vault.vault/").toString(), entry, "Bearer test")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)

        server.enqueue(
            MockResponse()
                .setResponseCode(
                    206,
                ).addHeader("Content-Range", "bytes 0-2/4")
                .setBody(okio.Buffer().write(byteArrayOf(1, 2, 3))),
        )
        val shortRange =
            assertThrows(OpenCloudException::class.java) {
                client.readProofPrefix(server.url("dav/Vault.vault/").toString(), entry, "Bearer test")
            }
        assertEquals(OpenCloudError.InvalidResponse, shortRange.error)
    }

    @Test fun `nested listing requires an established vault root`() {
        val unsupported =
            assertThrows(OpenCloudException::class.java) {
                client.list(server.url("dav/files/").toString(), path = "folder", authorization = "Bearer test")
            }
        assertEquals(OpenCloudError.Unsupported, unsupported.error)

        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                envelope(
                    response("/dav/drive/root/child/", "child", "child", true, ""),
                    response("/dav/drive/root/child/sub", "sub", "sub", false, "", size = 1),
                ),
            ),
        )
        val nested =
            client.list(
                server.url("dav/drive/root/").toString(),
                path = "child",
                authorization = "Bearer test",
                recognizedVaultRoot = true,
            )
        assertEquals("child", nested.root.rawName)
    }

    @Test fun `http access failure remains distinct from vault proof data`() {
        for (status in listOf(401, 403)) {
            server.enqueue(MockResponse().setResponseCode(status))
            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.list(server.url("dav/Secret.vault/").toString(), authorization = "Bearer test")
                }
            assertEquals(status, failure.statusCode)
            val expected = if (status == 401) OpenCloudError.AuthenticationRequired else OpenCloudError.AccessDenied
            assertEquals(expected, failure.error)
        }
    }

    @Test fun `oversized xml and ciphertext are rejected`() {
        server.enqueue(MockResponse().setBody("x".repeat(100)))
        val smallXml = VaultDavClient(OkHttpClient(), maxXmlBytes = 64, endpoints = EndpointPolicy(true))
        assertThrows(OpenCloudException::class.java) {
            smallXml.list(server.url("dav/Secret.vault/").toString(), authorization = "Bearer test")
        }

        server.enqueue(MockResponse().setBody(okio.Buffer().write(ByteArray(9) { 0 })))
        val entry =
            VaultDavEntry("id", "cipher", "cipher", false, 9, null, server.url("dav/Secret.vault/cipher").toString())
        val smallCipher = VaultDavClient(OkHttpClient(), maxCiphertextBytes = 8, endpoints = EndpointPolicy(true))
        assertThrows(OpenCloudException::class.java) {
            smallCipher.readCiphertext(server.url("dav/Secret.vault/").toString(), entry, "Bearer test")
        }
    }

    private fun envelope(vararg responses: String) =
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">${responses.joinToString(
            "",
        )}</d:multistatus>"

    @Suppress("LongParameterList")
    private fun response(
        href: String,
        id: String,
        name: String,
        folder: Boolean,
        extra: String = "",
        etag: String = "\"v1\"",
        size: Long = 0,
    ) = """<d:response><d:href>$href</d:href><d:propstat><d:prop>
        <d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype>
        <d:getcontentlength>$size</d:getcontentlength><d:getetag>$etag</d:getetag>
        <oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$extra
        </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
}
