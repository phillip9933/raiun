package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.concurrent.TimeUnit

class GuestPermissionsClientTest {
    private val target = GraphShareTarget("drive!id", "item!id")

    @Test fun serverNineEmptyFileAndFolderCollectionsAllowFirstInvitation() {
        // Derived from v9.0.0 apiSharingNg1/listPermissions.feature, including real
        // resource-specific roles, localized display names, descriptions and weights.
        listOf("file", "folder").forEach { kind ->
            MockWebServer().use { server ->
                server.start()
                val fixture =
                    checkNotNull(javaClass.getResource("/guest-permissions-v9-empty-$kind.json")).readText()
                val viewer = "b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5"
                val url = server.url("/").toString()
                server.enqueue(json(fixture))
                val listing = client().list(url, AUTH, target)
                assertEquals(emptyList<GuestPermission>(), listing.guests)
                assertEquals(GuestRole(viewer, "Can view"), listing.roles.first())
                assertEquals(if (kind == "file") 2 else 3, listing.roles.size)
                server.enqueue(json(fixture))
                server.enqueue(json("""{"value":[${guest(role = viewer)}]}"""))
                assertEquals(listOf(viewer), client().invite(url, AUTH, target, EMAIL, viewer).roles)
                assertEquals("GET", server.takeRequest().method)
                assertEquals("GET", server.takeRequest().method)
                assertEquals("POST", server.takeRequest().method)
                server.enqueue(json(fixture.replaceFirst("{", """{"value":[${guest(role = viewer)}],""")))
                assertEquals(
                    listOf(viewer),
                    client()
                        .list(url, AUTH, target)
                        .guests
                        .single()
                        .roles,
                )
                assertEquals("GET", server.takeRequest().method)
            }
        }
    }

    @Test fun omittedCollectionDoesNotRelaxMalformedRolesOrPresentValueValidation() {
        val withoutValue = listing().replace("\"value\":[],", "")
        val bodies =
            listOf(
                "{}",
                withoutValue.replace("\"@libre.graph.permissions.roles.allowedValues\"", "\"roles\""),
                withoutValue.replace(VIEWER, "invalid-role"),
                withoutValue.replace("\"Viewer\"", "null"),
                listing().replace("\"value\":[]", "\"value\":null"),
                listing().replace("\"value\":[]", "\"value\":{}"),
            )
        MockWebServer().use { server ->
            server.start()
            bodies.forEach { body ->
                server.enqueue(json(body))
                assertFailure(
                    OpenCloudError.InvalidResponse,
                ) { client().list(server.url("/").toString(), AUTH, target) }
            }
        }
    }

    @Test fun invitationResponseStillRequiresExactlyOnePermissionInValue() {
        MockWebServer().use { server ->
            server.start()
            val bodies =
                listOf("{}", """{"value":null}""", """{"value":[]}""", """{"value":[${guest()},${guest()}]}""")
            bodies.forEach { body ->
                server.enqueue(json(listing().replace("\"value\":[],", "")))
                server.enqueue(json(body))
                assertFailure(OpenCloudError.InvalidResponse) {
                    client().invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER)
                }
                assertEquals("GET", server.takeRequest().method)
                assertEquals("POST", server.takeRequest().method)
            }
        }
    }

    @Test fun listsOnlyExactGraphGuestsAndIgnoresLinksAndOtherIdentities() {
        MockWebServer().use { server ->
            server.start()
            val rows =
                """
                ${guest()},
                {"id":"member","roles":["unknown"],"grantedToV2":{"user":{"id":"member@example.test","@libre.graph.userType":"Member"}}},
                {"id":"group","grantedToV2":{"group":{"id":"group@example.test"}}},
                {"id":"federated","grantedToV2":{"user":{"id":"remote@example.test","@libre.graph.userType":"Federated"}}},
                {"id":"lowercase","grantedToV2":{"user":{"id":"guest@example.test","@libre.graph.userType":"guest"}}},
                {"id":"untyped","grantedToV2":{"user":{"id":"guest@example.test","userType":"Guest"}}},
                {"id":"public","link":{"webUrl":"https://secret.invalid/invitation-token"},"grantedToV2":{"user":{"id":"guest@example.test","@libre.graph.userType":"Guest"}}},
                {"id":"future-permission","customSecret":"never retain"}
                """.trimIndent()
            server.enqueue(json(listing(rows)))
            val result = client().list(server.url("/prefix/").toString(), AUTH, target)
            assertEquals(listOf(GuestPermission("guest-permission", EMAIL, listOf(VIEWER), EXPIRY)), result.guests)
            assertEquals(listOf(GuestRole(VIEWER, "Viewer"), GuestRole(EDITOR, "Editor")), result.roles)
            assertFalse(result.toString().contains("invitation-token"))
            val request = server.takeRequest()
            assertEquals("GET", request.method)
            assertEquals("/prefix/graph/v1beta1/drives/drive!id/items/item!id/permissions", request.path)
            assertEquals(AUTH, request.getHeader("Authorization"))
            assertEquals("application/json", request.getHeader("Accept"))
        }
    }

    @Test fun encodesOpaqueDriveItemAndPermissionIdsAsSingleSegments() {
        MockWebServer().use { server ->
            server.start()
            val unusual = GraphShareTarget("drive/a?b#c", "item/%2e/ü")
            server.enqueue(json(listing(guest(id = "permission/a?b"))))
            server.enqueue(MockResponse().setResponseCode(204))
            client().remove(server.url("/base/").toString(), AUTH, unusual, "permission/a?b")
            assertEquals(
                "/base/graph/v1beta1/drives/drive%2Fa%3Fb%23c/items/item%2F%252e%2F%C3%BC/permissions",
                server.takeRequest().path,
            )
            assertEquals(
                "/base/graph/v1beta1/drives/drive%2Fa%3Fb%23c/items/item%2F%252e%2F%C3%BC/permissions/permission%2Fa%3Fb",
                server.takeRequest().path,
            )
        }
    }

    @Test fun invitationUsesOnlyEmailServerRoleAndOptionalIsoExpiry() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(json(listing()))
            server.enqueue(json("""{"value":[${guest()}]}"""))
            val result = client().invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER, EXPIRY)
            assertEquals(EMAIL, result.email)
            assertEquals("GET", server.takeRequest().method)
            val invite = server.takeRequest()
            assertEquals("POST", invite.method)
            assertEquals("/graph/v1beta1/drives/drive!id/items/item!id/invite", invite.path)
            assertEquals(AUTH, invite.getHeader("Authorization"))
            assertEquals(
                Json.parseToJsonElement(
                    """{"recipients":[{"email":"$EMAIL"}],"roles":["$VIEWER"],"expirationDateTime":"$EXPIRY"}""",
                ),
                Json.parseToJsonElement(invite.body.readUtf8()),
            )
        }
    }

    @Test fun invitationWithoutExpiryOmitsExpirationField() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(json(listing()))
            server.enqueue(json("""{"value":[${guest(expiry = null)}]}"""))
            assertNull(client().invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER).expirationDateTime)
            server.takeRequest()
            assertEquals(
                Json.parseToJsonElement("""{"recipients":[{"email":"$EMAIL"}],"roles":["$VIEWER"]}"""),
                Json.parseToJsonElement(server.takeRequest().body.readUtf8()),
            )
        }
    }

    @Test fun updateAndRevokeRefreshGuestPermissionAndUseExactItemRoute() {
        MockWebServer().use { server ->
            server.start()
            val url = server.url("/").toString()
            server.enqueue(json(listing(guest())))
            server.enqueue(json(guest(role = EDITOR, expiry = null)))
            val updated = client().update(url, AUTH, target, "guest-permission", EDITOR)
            assertEquals(listOf(EDITOR), updated.roles)
            assertNull(updated.expirationDateTime)
            assertEquals("GET", server.takeRequest().method)
            val update = server.takeRequest()
            assertEquals("PATCH", update.method)
            assertEquals("/graph/v1beta1/drives/drive!id/items/item!id/permissions/guest-permission", update.path)
            assertEquals(
                Json.parseToJsonElement("""{"roles":["$EDITOR"],"expirationDateTime":null}"""),
                Json.parseToJsonElement(update.body.readUtf8()),
            )
            server.enqueue(json(listing(guest(role = EDITOR))))
            server.enqueue(MockResponse().setResponseCode(204))
            client().remove(url, AUTH, target, "guest-permission")
            assertEquals("GET", server.takeRequest().method)
            val revoke = server.takeRequest()
            assertEquals("DELETE", revoke.method)
            assertEquals(update.path, revoke.path)
            assertEquals(AUTH, revoke.getHeader("Authorization"))
        }
    }

    @Test fun rejectsUnknownRolesMissingRoleMetadataAndIncompleteOrMalformedListings() {
        MockWebServer().use { server ->
            server.start()
            val bodies =
                listOf(
                    """{"value":[]}""",
                    listing().replace(VIEWER, "viewer"),
                    listing(guest(role = "00000000-0000-0000-0000-000000000000")),
                    listing().dropLast(1) + """, "@odata.nextLink":"https://other.invalid/next"}""",
                    listing(guest() + "," + guest()),
                    listing(guest().replace(EXPIRY, "tomorrow")),
                    """{"value":{},"@libre.graph.permissions.roles.allowedValues":[]}""",
                    """{"value":[42],"@libre.graph.permissions.roles.allowedValues":[]}""",
                    "not JSON containing invitation-token",
                )
            bodies.forEach { body ->
                server.enqueue(json(body))
                assertFailure(
                    OpenCloudError.InvalidResponse,
                ) { client().list(server.url("/").toString(), AUTH, target) }
            }
        }
    }

    @Test fun mutationsRefuseUnknownRolesAndNonGuestPermissionIdsWithoutWriting() {
        MockWebServer().use { server ->
            server.start()
            val url = server.url("/").toString()
            server.enqueue(json(listing()))
            assertThrows(IllegalArgumentException::class.java) { client().invite(url, AUTH, target, EMAIL, "reader") }
            val member =
                """
                {"id":"member","roles":["$VIEWER"],"grantedToV2":{
                "user":{"id":"member@example.test","@libre.graph.userType":"Member"}}}
                """.trimIndent()
            server.enqueue(json(listing(member)))
            assertThrows(IllegalArgumentException::class.java) { client().update(url, AUTH, target, "member", VIEWER) }
            server.enqueue(json(listing(member)))
            assertThrows(IllegalArgumentException::class.java) { client().remove(url, AUTH, target, "member") }
            repeat(3) { assertEquals("GET", server.takeRequest().method) }
            assertEquals(3, server.requestCount)
        }
    }

    @Test fun rejectsInvalidEmailExpiryAndUnsafeResourceIdsBeforeAnyRequest() {
        val invalidIds = listOf("", " ", ".", "..", "bad\nvalue", "a".repeat(4097))
        invalidIds.forEach { id ->
            assertThrows(IllegalArgumentException::class.java) { GraphShareTarget(id, "item") }
            assertThrows(IllegalArgumentException::class.java) { GraphShareTarget("drive", id) }
        }
        MockWebServer().use { server ->
            server.start()
            val url = server.url("/").toString()
            listOf(
                "",
                "a",
                "name <guest@example.test>",
                "a@@example.test",
                "a\n@example.test",
                "a@example..test",
            ).forEach {
                assertThrows(IllegalArgumentException::class.java) { client().invite(url, AUTH, target, it, VIEWER) }
            }
            assertThrows(
                IllegalArgumentException::class.java,
            ) { client().invite(url, AUTH, target, EMAIL, VIEWER, "tomorrow") }
            assertThrows(IllegalArgumentException::class.java) { client().update(url, AUTH, target, "..", VIEWER) }
            assertEquals(0, server.requestCount)
        }
    }

    @Test fun errorsAreTypedAndNeverContainResponseSecrets() {
        MockWebServer().use { server ->
            server.start()
            mapOf(
                401 to OpenCloudError.AuthenticationRequired,
                403 to OpenCloudError.AccessDenied,
                404 to OpenCloudError.NotFound,
                409 to OpenCloudError.Conflict,
                429 to OpenCloudError.RateLimited(17),
                501 to OpenCloudError.Unsupported,
            ).forEach { (status, error) ->
                server.enqueue(
                    MockResponse().setResponseCode(status).setHeader("Retry-After", "17").setBody("invitation-token"),
                )
                assertFailure(error) { client().list(server.url("/").toString(), AUTH, target) }
            }
        }
    }

    @Test fun redirectsNeverSendCredentialsToAnotherOrigin() {
        MockWebServer().use { origin ->
            MockWebServer().use { other ->
                origin.start()
                other.start()
                origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/secret")))
                assertFailure(
                    OpenCloudError.HttpFailure(302),
                ) { client().list(origin.url("/").toString(), AUTH, target) }
                assertEquals(AUTH, origin.takeRequest().getHeader("Authorization"))
                assertEquals(0, other.requestCount)
            }
        }
    }

    @Test fun boundsDecodedMetadataAndKeepsSuppliedShorterDeadline() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(json(" ".repeat(2 * 1024 * 1024 + 1)))
            assertFailure(OpenCloudError.InvalidResponse) { client().list(server.url("/").toString(), AUTH, target) }
            server.enqueue(MockResponse().setBody(listing()).setBodyDelay(2, TimeUnit.SECONDS))
            val limited =
                GuestPermissionsClient(
                    OkHttpClient.Builder().callTimeout(100, TimeUnit.MILLISECONDS).build(),
                    EndpointPolicy(true),
                )
            val exception =
                assertThrows(OpenCloudException::class.java) { limited.list(server.url("/").toString(), AUTH, target) }
            assertFalse(exception.toString().contains("invitation-token"))
        }
    }

    @Test fun failedMutationIsNotRetriedAndMalformedSuccessFailsClosed() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(json(listing()))
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
            assertThrows(OpenCloudException::class.java) {
                client().invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER)
            }
            assertEquals("GET", server.takeRequest().method)
            assertEquals("POST", server.takeRequest().method)
            assertEquals(2, server.requestCount)
            server.enqueue(json(listing()))
            server.enqueue(json("""{"value":[{"id":"link","link":{"webUrl":"https://secret.invalid/token"}}]}"""))
            assertFailure(OpenCloudError.InvalidResponse) {
                client().invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER)
            }
        }
    }

    @Test fun mutationFenceRunsAfterDiscoveryAndCanPreventWrite() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(json(listing()))
            var fenceCalls = 0
            val fenced =
                GuestPermissionsClient(OkHttpClient(), EndpointPolicy(true)) {
                    fenceCalls++
                    if (fenceCalls == 2) {
                        assertEquals(1, server.requestCount)
                        throw OpenCloudException(OpenCloudError.AccessDenied)
                    }
                }
            assertFailure(
                OpenCloudError.AccessDenied,
            ) { fenced.invite(server.url("/").toString(), AUTH, target, EMAIL, VIEWER) }
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun productionPolicyRejectsHttpQueriesAndEmbeddedCredentials() {
        val strict = GuestPermissionsClient(OkHttpClient())
        listOf(
            "http://example.test/",
            "https://user:secret@example.test/",
            "https://example.test/?secret=token",
        ).forEach {
            assertFailure(OpenCloudError.Trust) { strict.list(it, AUTH, target) }
        }
    }

    private fun assertFailure(
        expected: OpenCloudError,
        operation: () -> Unit,
    ) {
        val exception = assertThrows(OpenCloudException::class.java, operation)
        assertEquals(expected, exception.error)
        assertFalse(exception.toString().contains("invitation-token"))
        assertNull(exception.cause)
    }

    private fun client() = GuestPermissionsClient(OkHttpClient(), EndpointPolicy(true))

    private fun json(body: String) = MockResponse().setBody(body).setHeader("Content-Type", "application/json")

    private fun listing(rows: String = "") =
        """
        {"value":[$rows],"@libre.graph.permissions.roles.allowedValues":[
        {"id":"$VIEWER","displayName":"Viewer"},{"id":"$EDITOR","displayName":"Editor"}]}
        """.trimIndent()

    private fun guest(
        id: String = "guest-permission",
        role: String = VIEWER,
        expiry: String? = EXPIRY,
    ) = """
        {"id":"$id","roles":["$role"],"expirationDateTime":${expiry?.let { "\"$it\"" } ?: "null"},
        "grantedToV2":{"user":{"id":"$EMAIL","displayName":"$EMAIL","@libre.graph.userType":"Guest"}}}
        """.trimIndent()

    private companion object {
        const val VIEWER = "a0a68c17-9b43-4c3c-a955-6c6c059f451d"
        const val EDITOR = "58c63c02-1d89-4572-916a-870abc5a1b7d"
        const val EMAIL = "guest@example.test"
        const val AUTH = "Bearer synthetic-test"
        const val EXPIRY = "2027-02-01T12:00:00Z"
    }
}
