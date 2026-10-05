package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteShare
import eu.opencloud.android.next.core.network.ShareRecipient
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class EncryptedLocationManagementRepositoryTest {
    @Test fun spaceRenameUsesGraphAndVerifiesFreshMetadata() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server)
                val repository = repository(server, root)
                val before = graphSpace(server, vault = true)
                val after = before.replace("Vault Space", "Renamed Space")
                server.enqueue(MockResponse().setBody(before))
                server.enqueue(MockResponse().setBody(after.removePrefix("{\"value\":[").removeSuffix("]}")))
                server.enqueue(MockResponse().setBody(after))
                val result = repository.updateSpace("account", root, { true }, name = "Renamed Space")
                assertEquals("Renamed Space", result.name)
                assertEquals(root.remoteVaultId, result.location.remoteVaultId)
                assertEquals("GET", takeRequest(server).method)
                val mutation = takeRequest(server)
                assertEquals("PATCH", mutation.method)
                assertEquals("{\"name\":\"Renamed Space\"}", mutation.body.readUtf8())
                assertEquals("GET", takeRequest(server).method)
                assertEquals(3, server.requestCount)
            }
        }

    @Test fun disabledEncryptedSpacesAreCataloguedFromGraphMetadataOnly() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val repository = repository(server, spaceRoot(server))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                val result = repository.disabledSpaces("account")
                assertEquals(1, result.size)
                assertTrue(result.single().isDisabled)
                assertEquals("drive", result.single().driveId)
                val request = takeRequest(server)
                assertEquals("GET", request.method)
                assertEquals("/graph/v1.0/drives", request.path?.substringBefore('?'))
                assertEquals(1, server.requestCount)
            }
        }

    @Test fun disablingAndRestoringUseBoundGraphIdentityAndVerifyState() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server)
                val repository = repository(server, root)
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                server.enqueue(MockResponse().setResponseCode(204))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                val disabled = repository.disableSpace("account", root, { true })
                assertTrue(disabled.isDisabled)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("GET", takeRequest(server).method)
                val disable = takeRequest(server)
                assertEquals("DELETE", disable.method)
                assertEquals("/graph/v1.0/drives/drive", disable.path)
                assertEquals("GET", takeRequest(server).method)

                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                server.enqueue(MockResponse().setBody(graphSpaceObject(server, vault = true)))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                val restored = repository.restoreDisabledSpace("account", disabled)
                assertFalse(restored.isDisabled)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("GET", takeRequest(server).method)
                val restore = takeRequest(server)
                assertEquals("PATCH", restore.method)
                assertEquals("T", restore.getHeader("Restore"))
                assertEquals("GET", takeRequest(server).method)
            }
        }

    @Test fun permanentDeleteRequiresDisabledVaultAndUsesPurgeThenVerifiesAbsence() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server).copy(isDisabled = true)
                val repository = repository(server, root)
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true, disabled = true)))
                server.enqueue(MockResponse().setResponseCode(204))
                server.enqueue(MockResponse().setBody("""{"value":[]}"""))
                repository.permanentlyDeleteDisabledSpace("account", root)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("GET", takeRequest(server).method)
                val purge = takeRequest(server)
                assertEquals("DELETE", purge.method)
                assertEquals("T", purge.getHeader("Purge"))
                assertEquals("GET", takeRequest(server).method)
            }
        }

    @Test fun lifecycleRejectsChangedRootAndActiveSpacePurgeBeforeMutation() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val active = spaceRoot(server)
                val repository = repository(server, active)
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                try {
                    repository.restoreDisabledSpace("account", active.copy(isDisabled = true, sourceRootId = "changed"))
                } catch (_: OpenCloudException) {
                }
                assertEquals(1, server.requestCount)
                takeRequest(server)

                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                try {
                    repository.permanentlyDeleteDisabledSpace("account", active)
                } catch (_: OpenCloudException) {
                }
                assertEquals(1, server.requestCount)
            }
        }

    @Test fun lifecycleUsesServerAuthorizationAfterExactIdentityValidation() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val disabled = spaceRoot(server).copy(isDisabled = true)
                val repository = repository(server, disabled)
                server.enqueue(
                    MockResponse().setBody(graphSpace(server, vault = true, disabled = true, ownerId = "other")),
                )
                server.enqueue(
                    MockResponse().setBody(graphSpace(server, vault = true, disabled = true, ownerId = "other")),
                )
                server.enqueue(MockResponse().setResponseCode(403))
                try {
                    repository.restoreDisabledSpace("account", disabled)
                    throw AssertionError("The server must reject this account's restore request.")
                } catch (_: OpenCloudException) {
                }
                assertEquals(3, server.requestCount)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("PATCH", takeRequest(server).method)
            }
        }

    @Test fun missingOrPlainGraphTargetNeverReachesPatch() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server)
                val repository = repository(server, root)
                server.enqueue(MockResponse().setBody("""{"value":[]}"""))
                try {
                    repository.updateSpace("account", root, { true }, name = "Changed")
                } catch (
                    _: OpenCloudException,
                ) {
                }
                assertEquals(1, server.requestCount)
                assertEquals("GET", takeRequest(server).method)

                server.enqueue(MockResponse().setBody(graphSpace(server, vault = false)))
                try {
                    repository.updateSpace("account", root, { true }, name = "Changed")
                } catch (
                    _: OpenCloudException,
                ) {
                }
                assertEquals(2, server.requestCount)
                assertEquals("GET", takeRequest(server).method)
            }
        }

    @Test fun revokedUnlockLeaseNeverReachesGraphOrOcs() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server)
                val repository = repository(server, root)
                try {
                    repository.addMember(
                        "account",
                        root,
                        ShareRecipient(OcsShareType.USER, "u", "User", null, true),
                        "editor",
                        { false },
                    )
                } catch (_: OpenCloudException) {
                }
                assertEquals(0, server.requestCount)
            }
        }

    @Test fun unadvertisedRoleNeverReachesGraphInvite() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = spaceRoot(server)
                val repository = repository(server, root)
                server.enqueue(MockResponse().setBody(graphSpace(server, vault = true)))
                server.enqueue(
                    MockResponse().setBody(
                        """{"value":[],"@libre.graph.permissions.roles.allowedValues":[{"id":"reader","displayName":"Viewer"}]}""",
                    ),
                )
                try {
                    repository.addMember(
                        "account",
                        root,
                        ShareRecipient(OcsShareType.USER, "u", "User", null, true),
                        "editor",
                        { true },
                    )
                } catch (_: IllegalArgumentException) {
                }
                assertEquals(2, server.requestCount)
                assertEquals("GET", takeRequest(server).method)
                assertEquals("GET", takeRequest(server).method)
            }
        }

    @Test fun unsupportedFolderPermissionNeverReachesOcsMutation() =
        runTest {
            MockWebServer().use { server ->
                server.start()
                val root = folderRoot().copy(canonicalServer = server.url("/").toString())
                val repository = repository(server, root)
                try {
                    repository.addFolderRootShare(
                        "account",
                        root,
                        ShareRecipient(OcsShareType.USER, "u", "User", null, true),
                        0,
                        { true },
                    )
                } catch (_: IllegalArgumentException) {
                }
                assertEquals(0, server.requestCount)
            }
        }

    @Test fun rootIdentityRejectsAnotherAccountServerDriveOrReplacedDavObject() {
        val root = folderRoot()
        assertTrue(root.sameRoot(root.copy(title = "Renamed")))
        assertFalse(root.sameRoot(root.copy(accountId = "other")))
        assertFalse(root.sameRoot(root.copy(canonicalServer = "https://other.example/")))
        assertFalse(root.sameRoot(root.copy(driveId = "other")))
        assertFalse(root.sameRoot(root.copy(sourceRootId = "other")))
        assertFalse(root.sameRoot(root.copy(remoteVaultId = "replacement")))
        assertFalse(root.sameRoot(root.copy(rootWebDavUrl = "https://cloud.example/dav/other")))
        assertFalse(root.sameRoot(root.copy(vaultPath = "another/Private.vault")))
    }

    @Test fun folderSharingNeverExposesPublicLinksOrDescendantShares() {
        val root = folderRoot()
        assertTrue(share(root.remoteVaultId).isExactFolderShare(root))
        assertFalse(share("child-id").isExactFolderShare(root))
        assertFalse(share(root.remoteVaultId, OcsShareType.PUBLIC_LINK).isExactFolderShare(root))
        assertFalse(share(root.remoteVaultId, folder = false).isExactFolderShare(root))
    }

    private fun folderRoot() =
        VaultLocation(
            accountId = "account",
            title = "Private.vault",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = "drive",
            remoteVaultId = "root-id",
            sourceRootId = "source-id",
            canonicalServer = "https://cloud.example/",
            rootWebDavUrl = "https://cloud.example/dav/drive",
            vaultPath = "Private.vault",
            isVaultRoot = true,
        )

    private fun spaceRoot(server: MockWebServer) =
        folderRoot().copy(
            title = "Vault Space",
            kind = VaultLocationKind.SPACE_VAULT,
            canonicalServer = server.url("/").toString(),
            rootWebDavUrl = server.url("/dav/drive").toString(),
            vaultPath = "",
        )

    private fun repository(
        server: MockWebServer,
        root: VaultLocation,
    ) = EncryptedLocationManagementRepository(
        EncryptedManagementDependencies(
            accountFor = { AccountEntity("account", server.url("/").toString(), "u", "User", "BASIC", false) },
            spaceRootsFor = { listOf(root) },
            folderRootsFor = { _, _, _ -> listOf(root) },
            authorizationFor = { "Bearer test" },
            clientFor = { OkHttpClient() },
            permitFor = { { true } },
            endpoints = EndpointPolicy(allowLoopbackHttp = true),
        ),
    )

    private fun graphSpace(
        server: MockWebServer,
        vault: Boolean,
        disabled: Boolean = false,
        ownerId: String = "u",
    ): String {
        val deleted = if (disabled) ",\"deleted\":{\"state\":\"trashed\"}" else ""
        return """{"value":[{"id":"drive","name":"Vault Space","driveType":"project","owner":{"user":{"id":"$ownerId","displayName":"User"}},"@libre.graph.contentType":"${if (vault) "application/vnd.opencloud.vault" else "plain"}","root":{"id":"source-id","webDavUrl":"${server.url(
            "/dav/drive",
        )}"$deleted}}]}"""
    }

    private fun graphSpaceObject(
        server: MockWebServer,
        vault: Boolean,
        disabled: Boolean = false,
    ): String = graphSpace(server, vault, disabled).removePrefix("""{"value":[""").removeSuffix("]}")

    private fun takeRequest(server: MockWebServer) =
        server.takeRequest(5, TimeUnit.SECONDS) ?: error("Expected an HTTP request within five seconds.")

    private fun share(
        resourceId: String,
        type: OcsShareType = OcsShareType.USER,
        folder: Boolean = true,
    ) = RemoteShare(
        id = "share",
        type = type,
        path = "/Private.vault",
        resourceId = resourceId,
        shareWith = "person",
        displayName = "Person",
        additionalInfo = null,
        permissions = 15,
        sharedAtEpochSeconds = 0,
        expiresAtEpochMillis = null,
        label = null,
        isFolder = folder,
        publicUrl = null,
    )
}
