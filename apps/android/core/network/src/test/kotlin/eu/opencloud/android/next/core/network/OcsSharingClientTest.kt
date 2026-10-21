package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.time.LocalDate

class OcsSharingClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: OcsSharingClient

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        client = OcsSharingClient(OkHttpClient())
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `lists received shares with typed fields`() {
        server.enqueue(ok(shareList()))

        val shares = client.listShares(baseUrl(), "Bearer token", sharedWithMe = true)

        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertTrue(request.requestUrl?.queryParameter("shared_with_me") == "true")
        assertOcsHeaders(request)
        assertEquals(OcsShareType.USER, shares.single().type)
        assertEquals("Quarterly plan.pdf", shares.single().displayName)
    }

    @Test fun `creates public share without exposing secret in result`() {
        server.enqueue(ok(singleShare(shareType = 3, name = "Review link")))

        val share =
            client.createShare(
                baseUrl(),
                "Bearer token",
                CreateShareRequest(
                    path = "/Quarterly plan.pdf",
                    type = OcsShareType.PUBLIC_LINK,
                    permissions = 1,
                    label = "Review link",
                    password = "do-not-log",
                    expirationDate = LocalDate.of(2026, 9, 30),
                ),
            )

        val requestBody = server.takeRequest().body.readUtf8()
        assertTrue(requestBody.contains("password=do-not-log"))
        assertTrue(requestBody.contains("expireDate=2026-09-30"))
        assertEquals("Review link", share.label)
        assertEquals("https://private.example/s/secret", share.publicUrl)
        assertFalse(share.toString().contains("do-not-log"))
        assertFalse(share.toString().contains("private.example"))
    }

    @Test fun `updates permissions and revokes share`() {
        server.enqueue(ok(singleShare(permissions = 3)))
        server.enqueue(ok("[]"))

        client.updateShare(baseUrl(), "Bearer token", "share/id", UpdateShareRequest(permissions = 3))
        client.revokeShare(baseUrl(), "Bearer token", "share/id")

        val update = server.takeRequest()
        val revoke = server.takeRequest()
        assertEquals("PUT", update.method)
        assertTrue(update.path.orEmpty().contains("share%2Fid"))
        assertEquals("permissions=3", update.body.readUtf8())
        assertEquals("DELETE", revoke.method)
    }

    @Test fun `sharing a discovered resource uses its space reference without a legacy home path`() {
        server.enqueue(ok(singleShare(shareType = 3)))
        client.createShare(
            baseUrl(),
            "Bearer token",
            CreateShareRequest(
                path = "/nested/Plan.pdf",
                type = OcsShareType.PUBLIC_LINK,
                resourceId = "storage\$space!file",
            ),
        )
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("space=storage%24space%21file"))
        assertFalse(body.contains("path="))
        assertFalse(body.contains("shareWith="))
        server.enqueue(ok(shareList()))
        client.listShares(baseUrl(), "Bearer token", path = "/Plan.pdf", resourceId = "storage\$space!file")
        val url = server.takeRequest().requestUrl!!
        assertEquals("storage\$space!file", url.queryParameter("space"))
        assertEquals(null, url.queryParameter("path"))
    }

    @Test fun `searches users and groups and keeps exact matches first`() {
        server.enqueue(
            ok(
                """{"exact":{"users":[{"label":"Alice","value":{"shareType":0,"shareWith":"alice"}}],"groups":[],"remotes":[]},"users":[],"groups":[{"label":"Design","value":{"shareType":1,"shareWith":"design"}}],"remotes":[]}""",
            ),
        )

        val values = client.searchRecipients(baseUrl(), "Bearer token", "ali")

        assertEquals(listOf("alice", "design"), values.map(ShareRecipient::shareWith))
        assertTrue(values.first().exact)
    }

    @Test fun `OCS failure returns safe message without response secrets`() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"ocs":{"meta":{"status":"failure","statuscode":403,"message":"Permission denied"},"data":{"url":"https://private.example/token","token":"secret-token"}}}""",
            ),
        )

        val error =
            assertThrows(TransferHttpException::class.java) {
                client.listShares(baseUrl(), "Bearer token")
            }

        assertEquals(403, error.statusCode)
        assertEquals("Access was denied.", error.message)
        assertFalse(error.message.orEmpty().contains("secret-token"))
        assertFalse(error.message.orEmpty().contains("private.example"))
    }

    @Test fun `HTTP 400 password rejection returns public link guidance`() {
        server.enqueue(MockResponse().setResponseCode(400).setBody("missing required password"))

        val error =
            assertThrows(TransferHttpException::class.java) {
                client.createShare(
                    baseUrl(),
                    "Bearer token",
                    CreateShareRequest(path = "/Plan.pdf", type = OcsShareType.PUBLIC_LINK),
                )
            }

        assertEquals(400, error.statusCode)
        assertEquals("This server requires a password for public links.", error.message)
    }

    @Test fun `OCS 400 password rejection returns public link guidance`() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"ocs":{"meta":{"status":"failure","statuscode":400,"message":"Password is required"},"data":[]}}""",
            ),
        )

        val error =
            assertThrows(TransferHttpException::class.java) {
                client.createShare(
                    baseUrl(),
                    "Bearer token",
                    CreateShareRequest(path = "/Plan.pdf", type = OcsShareType.PUBLIC_LINK),
                )
            }

        assertEquals(400, error.statusCode)
        assertEquals("This server requires a password for public links.", error.message)
    }

    private fun assertOcsHeaders(request: okhttp3.mockwebserver.RecordedRequest) {
        assertEquals("Bearer token", request.getHeader("Authorization"))
        assertEquals("true", request.getHeader("OCS-APIREQUEST"))
        assertEquals("application/json", request.getHeader("Accept"))
        assertTrue(request.getHeader("X-Request-ID").orEmpty().isNotBlank())
    }

    @Test fun `sharing rejections expose safe categories rather than raw server details`() {
        val cases =
            mapOf(
                "could not parse space reference" to ShareRejection.RESOURCE_REFERENCE,
                "Can not share space root" to ShareRejection.SPACE_ROOT,
                "Could not create permission from permission key" to ShareRejection.PERMISSIONS,
                "Password too short" to ShareRejection.PASSWORD_POLICY,
                "invalid datetime format" to ShareRejection.EXPIRATION,
                "unrecognized response https://secret.invalid/token" to ShareRejection.UNKNOWN,
            )
        cases.forEach { (message, reason) ->
            server.enqueue(MockResponse().setResponseCode(400).setBody(message))
            val error =
                assertThrows(TransferHttpException::class.java) {
                    client.createShare(baseUrl(), "Bearer token", CreateShareRequest("/file", OcsShareType.PUBLIC_LINK))
                }
            assertEquals(OpenCloudError.ShareRejected(reason), error.error)
            assertFalse(error.message.orEmpty().contains("secret.invalid"))
        }
    }

    @Test fun `server password minimum errors without password keyword become safe actionable guidance`() {
        val message =
            "At least 12 characters are required\\n" +
                "at least 1 uppercase letters are required\\n" +
                "at least 2 numbers are required\\n" +
                "at least 1 special characters are required !secret-value"
        listOf(400, 200).forEach { httpStatus ->
            server.enqueue(
                MockResponse().setResponseCode(httpStatus).setBody(
                    """{"ocs":{"meta":{"statuscode":400,"message":"$message"},"data":[]}}""",
                ),
            )
            val error =
                assertThrows(TransferHttpException::class.java) {
                    client.createShare(baseUrl(), "Bearer token", CreateShareRequest("/file", OcsShareType.PUBLIC_LINK))
                }
            val rejection = error.error as OpenCloudError.ShareRejected
            assertEquals(ShareRejection.PASSWORD_POLICY, rejection.reason)
            assertEquals(12, rejection.passwordMinimums[PasswordCharacterClass.LENGTH])
            assertEquals(1, rejection.passwordMinimums[PasswordCharacterClass.UPPERCASE])
            assertEquals(2, rejection.passwordMinimums[PasswordCharacterClass.DIGITS])
            assertEquals(1, rejection.passwordMinimums[PasswordCharacterClass.SPECIAL])
            assertTrue(error.message.orEmpty().contains("at least 1 uppercase letters"))
            assertFalse(error.message.orEmpty().contains("secret-value"))
        }
    }

    @Test fun `password strength rules must not be mistaken for missing password`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(
                    400,
                ).setBody("Password validation: at least 1 lowercase letters are required"),
        )
        val error =
            assertThrows(TransferHttpException::class.java) {
                client.createShare(baseUrl(), "Bearer token", CreateShareRequest("/file", OcsShareType.PUBLIC_LINK))
            }
        assertEquals(
            OpenCloudError.ShareRejected(ShareRejection.PASSWORD_POLICY, mapOf(PasswordCharacterClass.LOWERCASE to 1)),
            error.error,
        )
    }

    private fun baseUrl() = server.url("/").toString()

    private fun ok(data: String) =
        MockResponse().setResponseCode(200).setBody(
            """{"ocs":{"meta":{"status":"ok","statuscode":100,"message":"OK"},"data":$data}}""",
        )

    private fun shareList() = "[${singleShareData()}]"

    private fun singleShare(
        shareType: Int = 0,
        permissions: Int = 1,
        name: String = "",
    ) = singleShareData(shareType, permissions, name)

    private fun singleShareData(
        shareType: Int = 0,
        permissions: Int = 1,
        name: String = "",
    ) =
        """{"id":"42","share_type":$shareType,"share_with":"alice","share_with_displayname":"Quarterly plan.pdf","path":"/Quarterly plan.pdf","item_source":"item-42","item_type":"file","permissions":$permissions,"stime":1700000000,"name":"$name","url":"https://private.example/s/secret","token":"secret"}"""
}
